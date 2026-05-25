# Copyright 2023, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from __future__ import annotations

from aiven.client import AivenClient
from aiven.client.client import Error, ResponseError, RetrySpec
from http import HTTPStatus
from typing import Any
from unittest import mock
from unittest.mock import patch

import json
import pytest


class MockResponse:
    def __init__(
        self,
        status_code: int | HTTPStatus,
        json_data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
    ):
        self.status_code = status_code.value if isinstance(status_code, HTTPStatus) else status_code
        self.json_data = json_data
        if content is not None:
            self.content = content
        elif json_data is not None:
            self.content = json.dumps(json_data).encode("utf-8")
        else:
            self.content = b""
        self.headers = {} if headers is None else headers
        self.text = self.content.decode("utf-8")
        self.reason = ""

    def json(self) -> Any:
        return self.json_data


@pytest.mark.parametrize(
    "response",
    [
        MockResponse(status_code=HTTPStatus.NO_CONTENT),
        MockResponse(status_code=HTTPStatus.CREATED),
    ],
)
def test_no_content_returned_from_api(response: MockResponse) -> None:
    aiven_client = AivenClient("")
    with mock.patch("aiven.client.client.AivenClientBase._execute", return_value=response):
        assert aiven_client.verify(aiven_client.post, "/") == {}
        assert aiven_client.verify(aiven_client.patch, "/") == {}
        assert aiven_client.verify(aiven_client.put, "/") == {}
        assert aiven_client.verify(aiven_client.delete, "/") == {}


@pytest.mark.parametrize(
    "response,expected_result",
    [
        (
            MockResponse(
                status_code=HTTPStatus.OK,
                headers={"Content-Type": "application/octet-stream"},
                content=b"foo",
            ),
            b"foo",
        ),
        (
            MockResponse(status_code=HTTPStatus.OK, headers={"Content-Type": "application/json"}, json_data={}),
            {},
        ),
        (
            MockResponse(
                status_code=HTTPStatus.OK,
                headers={"Content-Type": "application/json"},
                json_data={},
                content=b"foo",
            ),
            {},
        ),
        (
            MockResponse(
                status_code=HTTPStatus.OK,
                headers={"Content-Type": "application/json"},
                json_data={"foo": "bar"},
                content=b"foo",
            ),
            {"foo": "bar"},
        ),
        (
            MockResponse(
                status_code=HTTPStatus.OK,
                headers={"Content-Type": "application/octet-stream"},
                json_data={"foo": "bar"},
                content=b"foo",
            ),
            b"foo",
        ),
    ],
)
def test_response_processing(response: MockResponse, expected_result: Any) -> None:
    def operation() -> MockResponse:
        return response

    aiven_client = AivenClient("")
    assert aiven_client._process_response(response=response, op=operation, path="") == expected_result  # type: ignore


def test_response_processing_result_key() -> None:
    expected_value = 2
    response = MockResponse(
        status_code=HTTPStatus.OK,
        headers={"Content-Type": "application/json"},
        json_data={"foo": 1, "bar": expected_value, "spam": 3},
    )

    def operation() -> MockResponse:
        return response

    aiven_client = AivenClient("")
    assert (
        aiven_client._process_response(response=response, op=operation, path="", result_key="bar")  # type: ignore
        == expected_value
    )


def test_response_processing_error_raise() -> None:
    response = MockResponse(
        status_code=HTTPStatus.OK,
        headers={"Content-Type": "application/json"},
        json_data={"foo": 1, "bar": 2, "spam": 3, "error": "test error"},
    )

    def operation() -> MockResponse:
        """test operation"""
        return response

    aiven_client = AivenClient("test_base_url")

    with pytest.raises(ResponseError) as e:
        aiven_client._process_response(response=response, op=operation, path="", result_key="bar")  # type: ignore
        assert (
            str(e)
            == "server returned error: test operation test_base_url {'foo': 1, 'bar': 2, 'spam': 3, 'error': 'test error'}"
        )


@pytest.mark.parametrize(
    "response_text, status, expected_str",
    [
        (
            '{"errors":[{"error_code":"kafka_topic_invalid_config","message":"bad config",'
            '"status":400}],"message":"Replication factor for diskless topics cannot be different than 1"}',
            400,
            "Replication factor for diskless topics cannot be different than 1 (status 400)",
        ),
        (
            '{"message":"Not found"}',
            404,
            "Not found (status 404)",
        ),
        (
            "plain text error",
            500,
            "plain text error (status 500)",
        ),
        (
            '{"errors":[]}',
            422,
            '{"errors":[]} (status 422)',
        ),
    ],
)
def test_error_str(response_text: str, status: int, expected_str: str) -> None:
    response = MockResponse(status_code=status, content=response_text.encode("utf-8"))
    error = Error(response, status)  # type: ignore[arg-type]
    assert str(error) == expected_str


class TestGetRetrySpec:
    def test_falls_back_to_default_default_spec_when_matching_operation(self) -> None:
        client = AivenClient("foo.test")
        assert client._get_retry_spec(client.get, None) == client.DEFAULT_RETRY

    def test_falls_back_to_given_default_spec_when_matching_operation(self) -> None:
        spec = RetrySpec(http_methods=("GET", "PUT"))
        client = AivenClient("foo.test", default_retry_spec=spec)
        assert client._get_retry_spec(client.put, None) == spec

    def test_falls_back_to_no_retry_when_not_matching_operation(self) -> None:
        client = AivenClient("foo.test")
        assert client._get_retry_spec(client.post, None) == client.NO_RETRY

    def test_can_pass_integer_attempts(self) -> None:
        client = AivenClient("foo.test")
        attempts = 42
        assert client._get_retry_spec(client.get, attempts) == RetrySpec(attempts=attempts)

    def test_can_pass_retry_spec(self) -> None:
        client = AivenClient("foo.test")
        given_spec = RetrySpec(attempts=52)
        assert client._get_retry_spec(client.get, given_spec) is given_spec


def test_byoc_tags_list() -> None:
    aiven_client = AivenClient("test_base_url")

    with patch.object(aiven_client.session, "put") as put_mock:
        put_mock.return_value = MockResponse(
            status_code=HTTPStatus.OK,
            headers={"Content-Type": "application/json"},
            json_data={
                "custom_cloud_environment": {
                    "cloud_provider": "aws",
                    "cloud_region": "eu-west-2",
                    "contact_emails": [],
                    "custom_cloud_environment_id": "d6a490ad-f43d-49d8-b3e5-45bc5dbfb387",
                    "deployment_model": "standard",
                    "reserved_cidr": "10.1.0.0/24",
                    "display_name": "Another name",
                    "state": "draft",
                    "tags": {
                        "key_1": "value_1",
                        "key_2": "",
                        "byoc_resource_tag:key_3": "value_3",
                        "byoc_resource_tag:key_4": "",
                        "byoc_resource_tag:key_5": "byoc_resource_tag:keep-the-whole-value-5",
                    },
                }
            },
        )

        response = aiven_client.list_byoc_tags(
            organization_id="org123456789a",
            byoc_id="d6a490ad-f43d-49d8-b3e5-45bc5dbfb387",
        )

        assert response == {
            "tags": {
                "key_1": "value_1",
                "key_2": "",
                "byoc_resource_tag:key_3": "value_3",
                "byoc_resource_tag:key_4": "",
                "byoc_resource_tag:key_5": "byoc_resource_tag:keep-the-whole-value-5",
            },
        }

        put_mock.assert_called_once_with(
            "test_base_url/v1/organization/org123456789a/custom-cloud-environments/d6a490ad-f43d-49d8-b3e5-45bc5dbfb387",
            headers={"content-type": "application/json"},
            params=None,
            data="{}",
        )


def test_byoc_tags_update() -> None:
    aiven_client = AivenClient("test_base_url")

    with patch.object(aiven_client.session, "put") as put_mock:
        put_mock.return_value = MockResponse(
            status_code=HTTPStatus.OK,
            headers={"Content-Type": "application/json"},
            json_data={
                "custom_cloud_environment": {
                    "cloud_provider": "aws",
                    "cloud_region": "eu-west-2",
                    "contact_emails": [],
                    "custom_cloud_environment_id": "d6a490ad-f43d-49d8-b3e5-45bc5dbfb387",
                    "deployment_model": "standard",
                    "reserved_cidr": "10.1.0.0/24",
                    "display_name": "Another name",
                    "state": "draft",
                    "tags": {
                        "byoc_resource_tag:key_1": "value_1",
                        "byoc_resource_tag:key_2": "",
                        "byoc_resource_tag:key_5": "byoc_resource_tag:keep-the-whole-value-5",
                    },
                }
            },
        )

        response = aiven_client.update_byoc_tags(
            organization_id="org123456789a",
            byoc_id="d6a490ad-f43d-49d8-b3e5-45bc5dbfb387",
            tag_updates={
                "byoc_resource_tag:key_1": "value_1",
                "byoc_resource_tag:key_2": "",
                "byoc_resource_tag:key_3": None,
                "key_4": None,
                "byoc_resource_tag:key_5": "byoc_resource_tag:keep-the-whole-value-5",
            },
        )

        assert response == {"message": "tags updated"}

        put_mock.assert_called_once_with(
            "test_base_url/v1/organization/org123456789a/custom-cloud-environments/d6a490ad-f43d-49d8-b3e5-45bc5dbfb387",
            headers={"content-type": "application/json"},
            params=None,
            data=(
                '{"tags": {'
                '"byoc_resource_tag:key_1": "value_1", '
                '"byoc_resource_tag:key_2": "", '
                '"byoc_resource_tag:key_3": null, '
                '"key_4": null, '
                '"byoc_resource_tag:key_5": "byoc_resource_tag:keep-the-whole-value-5"}}'
            ),
        )


def test_byoc_tags_replace() -> None:
    aiven_client = AivenClient("test_base_url")

    with patch.object(aiven_client.session, "put") as put_mock:
        put_mock.return_value = MockResponse(
            status_code=HTTPStatus.OK,
            headers={"Content-Type": "application/json"},
            json_data={
                "custom_cloud_environment": {
                    "cloud_provider": "aws",
                    "cloud_region": "eu-west-2",
                    "contact_emails": [],
                    "custom_cloud_environment_id": "d6a490ad-f43d-49d8-b3e5-45bc5dbfb387",
                    "deployment_model": "standard",
                    "reserved_cidr": "10.1.0.0/24",
                    "display_name": "Another name",
                    "state": "draft",
                    "tags": {
                        "byoc_resource_tag:key_1": "value_1",
                        "byoc_resource_tag:key_2": "",
                        "byoc_resource_tag:key_3": "byoc_resource_tag:keep-the-whole-value-3",
                    },
                }
            },
        )

        response = aiven_client.replace_byoc_tags(
            organization_id="org123456789a",
            byoc_id="d6a490ad-f43d-49d8-b3e5-45bc5dbfb387",
            tags={
                "byoc_resource_tag:key_1": "value_1",
                "byoc_resource_tag:key_2": "",
                "byoc_resource_tag:key_3": "byoc_resource_tag:keep-the-whole-value-3",
            },
        )

        assert response == {"message": "tags updated"}

        put_mock.assert_called_once_with(
            "test_base_url/v1/organization/org123456789a/custom-cloud-environments/d6a490ad-f43d-49d8-b3e5-45bc5dbfb387",
            headers={"content-type": "application/json"},
            params=None,
            data=(
                '{"tags": {'
                '"byoc_resource_tag:key_1": "value_1", '
                '"byoc_resource_tag:key_2": "", '
                '"byoc_resource_tag:key_3": "byoc_resource_tag:keep-the-whole-value-3"}}'
            ),
        )


def test_refresh_service_privatelink_aws() -> None:
    aiven_client = AivenClient("test_base_url")

    with patch.object(aiven_client.session, "post") as post_mock:
        post_mock.return_value = MockResponse(
            status_code=HTTPStatus.OK,
            headers={"Content-Type": "application/json"},
            json_data={"message": "refreshed"},
        )

        response = aiven_client.refresh_service_privatelink_aws(
            project="new-project-name",
            service="kafka-2921638b",
        )

        assert response == {"message": "refreshed"}

        post_mock.assert_called_once_with(
            "test_base_url/v1/project/new-project-name/service/kafka-2921638b/privatelink/aws/refresh",
            headers={"content-type": "application/octet-stream"},
            params=None,
            data=None,
        )


UPGRADE_STEP = {
    "step_id": "3a718c8f-57cb-474e-a14f-8f5a7c63a751",
    "source_project_name": "src-project",
    "source_service_name": "src-service",
    "destination_project_name": "dst-project",
    "destination_service_name": "dst-service",
    "auto_validation_delay_days": 7,
    "last_validation": None,
}


def test_upgrade_pipeline_step_create() -> None:
    aiven_client = AivenClient("test_base_url")

    with patch.object(aiven_client.session, "post") as post_mock:
        post_mock.return_value = MockResponse(
            status_code=HTTPStatus.OK,
            headers={"Content-Type": "application/json"},
            json_data=UPGRADE_STEP,
        )

        response = aiven_client.upgrade_pipeline_step_create(
            organization_id="org123456789a",
            source_project_name="src-project",
            source_service_name="src-service",
            destination_project_name="dst-project",
            destination_service_name="dst-service",
            auto_validation_delay_days=7,
        )
        assert response == UPGRADE_STEP

        post_mock.assert_called_once_with(
            "test_base_url/v1/organization/org123456789a/upgrade-pipeline/steps",
            headers={"content-type": "application/json"},
            params=None,
            data=(
                '{"source_project_name": "src-project", '
                '"source_service_name": "src-service", '
                '"destination_project_name": "dst-project", '
                '"destination_service_name": "dst-service", '
                '"auto_validation_delay_days": 7}'
            ),
        )


def test_upgrade_pipeline_step_update() -> None:
    aiven_client = AivenClient("test_base_url")

    with patch.object(aiven_client.session, "patch") as patch_mock:
        patch_mock.return_value = MockResponse(
            status_code=HTTPStatus.OK,
            headers={"Content-Type": "application/json"},
            json_data=UPGRADE_STEP,
        )

        response = aiven_client.upgrade_pipeline_step_update(
            organization_id="org123456789a",
            step_id="3a718c8f-57cb-474e-a14f-8f5a7c63a751",
            auto_validation_delay_days=14,
        )
        assert response == UPGRADE_STEP

        patch_mock.assert_called_once_with(
            "test_base_url/v1/organization/org123456789a/upgrade-pipeline/steps/3a718c8f-57cb-474e-a14f-8f5a7c63a751",
            headers={"content-type": "application/json"},
            params=None,
            data=('{"auto_validation_delay_days": 14}'),
        )


def test_upgrade_pipeline_step_delete() -> None:
    aiven_client = AivenClient("test_base_url")

    with patch.object(aiven_client.session, "delete") as delete_mock:
        delete_mock.return_value = MockResponse(
            status_code=HTTPStatus.NO_CONTENT,
            content=None,
        )

        response = aiven_client.upgrade_pipeline_step_delete(
            organization_id="org123456789a",
            step_id="3a718c8f-57cb-474e-a14f-8f5a7c63a751",
        )
        assert response == {}

        delete_mock.assert_called_once_with(
            "test_base_url/v1/organization/org123456789a/upgrade-pipeline/steps/3a718c8f-57cb-474e-a14f-8f5a7c63a751",
            headers={"content-type": "application/octet-stream"},
            params=None,
            data=None,
        )


def test_upgrade_pipeline_step_get() -> None:
    aiven_client = AivenClient("test_base_url")

    with patch.object(aiven_client.session, "get") as get_mock:
        get_mock.return_value = MockResponse(
            status_code=HTTPStatus.OK,
            headers={"Content-Type": "application/json"},
            json_data=UPGRADE_STEP,
        )

        response = aiven_client.upgrade_pipeline_step_get(
            organization_id="org123456789a", step_id="3a718c8f-57cb-474e-a14f-8f5a7c63a751"
        )
        assert response == UPGRADE_STEP

        get_mock.assert_called_once_with(
            "test_base_url/v1/organization/org123456789a/upgrade-pipeline/steps/3a718c8f-57cb-474e-a14f-8f5a7c63a751",
            headers={"content-type": "application/octet-stream"},
            params=None,
            data=None,
        )


def test_upgrade_pipeline_step_list() -> None:
    aiven_client = AivenClient("test_base_url")

    with patch.object(aiven_client.session, "get") as get_mock:
        get_mock.return_value = MockResponse(
            status_code=HTTPStatus.OK,
            headers={"Content-Type": "application/json"},
            json_data={"steps": UPGRADE_STEP},
        )

        response = aiven_client.upgrade_pipeline_step_list(organization_id="org123456789a")
        assert response == {"steps": UPGRADE_STEP}

        get_mock.assert_called_once_with(
            "test_base_url/v1/organization/org123456789a/upgrade-pipeline/steps",
            headers={"content-type": "application/octet-stream"},
            params=None,
            data=None,
        )


def test_upgrade_pipeline_step_validate() -> None:
    aiven_client = AivenClient("test_base_url")

    with patch.object(aiven_client.session, "post") as post_mock:
        post_mock.return_value = MockResponse(
            status_code=HTTPStatus.OK,
            headers={"Content-Type": "application/json"},
            json_data=UPGRADE_STEP,
        )

        response = aiven_client.upgrade_pipeline_step_validate(
            project_name="src-project",
            service_name="src-service",
            comment="validated",
        )
        assert response == UPGRADE_STEP

        post_mock.assert_called_once_with(
            "test_base_url/v1/project/src-project/service/src-service/upgrade-validation",
            headers={"content-type": "application/json"},
            params=None,
            data='{"comment": "validated"}',
        )
