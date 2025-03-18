# Copyright 2015, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.
from __future__ import annotations
from typing import Callable
from aiven.client.account_cli import AivenAccountOrganisationCLI
from . import argx
from aiven.client.common_cli import AivenCommonCLI
from aiven.client.opensearch_cli import AivenOpenSearchCLI


class AivenCLI(
    AivenCommonCLI,
    AivenAccountOrganisationCLI,
    AivenUserCLI,
    AivenPrivateLinkCLI,
    AivenOpenSearchCLI,
):
    def pre_run(self, func: Callable[[], int | None]) -> None:
        self.client = self.client_factory(
            base_url=self.args.url,
            show_http=self.args.show_http,
            request_timeout=self.args.request_timeout,
        )
        # Always set CA if we have anything set at the command line or in the env
        if self.args.auth_ca is not None:
            self.client.set_ca(self.args.auth_ca)
        if func == self.user__create:
            # "user create" doesn't use authentication (yet)
            return

        if not getattr(func, "no_auth", False):
            auth_token = self._get_auth_token()
            if auth_token:
                self.client.set_auth_token(auth_token)
            elif not getattr(func, "optional_auth", False):
                raise argx.UserError("not authenticated: please login first with 'avn user login'")


if __name__ == "__main__":
    AivenCLI().main()
