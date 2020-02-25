from unittest import mock
from unittest.mock import Mock

import pytest

from aiven.client import AivenClient
from aiven.client.client import Error


def test_it_raises_an_error_when_something_unexpected_happens_while_listing_project_invoices():
    with pytest.raises(Error):
        mock_response_content = {
            "message": "Authentication failed",
            "errors": [
                {
                    "status": "403",
                    "message": "Authentication failed"
                }
            ]
        }

        with mock.patch('requests.sessions') as session:
            mock_response = Mock()
            mock_response.status_code = "400"
            mock_response.headers = {}
            mock_response.text = mock_response_content
            mock_response.json.return_value = mock_response.text

            session.get.return_value = mock_response

            client = AivenClient(base_url='http://the-aiven-api-url')
            client.session = session

            client.get_project_invoices('the_project_id')


def test_it_lists_the_project_invoices():
    mock_response_content = {
        "errors": [
            []
        ],
        "invoices": [
            {
                "currency": "USD",
                "download_cookie": "the_download_cookie_value",
                "invoice_number": "a1ea-52",
                "period_begin": "the_period_begin_value",
                "period_end": "the_period_end_value",
                "state": "paid",
                "total_inc_vat": "42.30",
                "total_vat_zero": "42.30"
            }
        ],
        "message": "Completed"
    }

    with mock.patch('requests.sessions') as session:
        mock_response = Mock()
        mock_response.status_code = "200"
        mock_response.headers = {}
        mock_response.text = mock_response_content
        mock_response.json.return_value = mock_response.text

        session.get.return_value = mock_response

        client = AivenClient(base_url='http://the-aiven-api-url')
        client.session = session

        response = client.get_project_invoices('the_project_id')

        assert response == [
            {
                "currency": "USD",
                "download_cookie": "the_download_cookie_value",
                "invoice_number": "a1ea-52",
                "period_begin": "the_period_begin_value",
                "period_end": "the_period_end_value",
                "state": "paid",
                "total_inc_vat": "42.30",
                "total_vat_zero": "42.30"
            }
        ]
