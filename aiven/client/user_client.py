# Copyright 2025, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from __future__ import annotations

from aiven.client.base_client import AivenClientBase
from typing import Any, Mapping, Sequence, TYPE_CHECKING

try:
    from .version import __version__
except ImportError:
    __version__ = "UNKNOWN"

if TYPE_CHECKING:
    pass

UNCHANGED = object()  # used as a sentinel value


class AivenUserClient(AivenClientBase):
    def authenticate_user(self, email: str, password: str, otp: str | None = None, tenant_id: str | None = None) -> Mapping:
        body = {
            "email": email,
            "password": password,
        }
        if otp is not None:
            body["otp"] = otp
        if tenant_id is not None:
            body["tenant"] = tenant_id

        return self.verify(self.post, "/userauth", body=body)

    def create_user(self, email: str, password: str | None, real_name: str, *, tenant: str | None = None) -> Mapping:
        request = {
            "email": email,
            "real_name": real_name,
        }
        if tenant is not None:
            request["tenant"] = tenant
        if password is not None:
            request["password"] = password
        return self.verify(self.post, "/user", body=request)

    def get_user_info(self) -> Mapping:
        return self.verify(self.get, "/me", result_key="user")

    def access_token_create(
        self, description: str, extend_when_used: bool = False, max_age_seconds: int | None = None
    ) -> Mapping:
        request = {
            "description": description,
            "extend_when_used": extend_when_used,
            "max_age_seconds": max_age_seconds,
        }
        return self.verify(self.post, "/access_token", body=request)

    def access_token_revoke(self, token_prefix: str) -> Mapping:
        return self.verify(self.delete, self.build_path("access_token", token_prefix))

    def access_token_update(self, token_prefix: str, description: str) -> Mapping:
        request = {"description": description}
        return self.verify(self.put, self.build_path("access_token", token_prefix), body=request)

    def access_tokens_list(self) -> Sequence[dict[str, Any]]:
        return self.verify(self.get, "/access_token", result_key="tokens")

    def expire_user_tokens(self) -> Mapping:
        return self.verify(self.post, "/me/expire_tokens")

    def change_user_password(self, current_password: str, new_password: str) -> Mapping:
        request = {
            "password": current_password,
            "new_password": new_password,
        }
        return self.verify(self.put, "/me/password", body=request)
