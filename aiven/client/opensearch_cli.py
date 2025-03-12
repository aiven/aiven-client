# Copyright 2025, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.

from __future__ import annotations

from aiven.client.base_cli import AivenBaseCLI
from aiven.client.cliarg import arg


class AivenOpenSearchSecurityCLI(AivenBaseCLI):
    @arg.project
    @arg.service_name
    def service__opensearch__security_management__status(self) -> None:
        """Show status of the opensearch security"""
        response = self.client.opensearch_security_get(
            project=self.get_project(),
            service=self.args.service_name,
        )
        available = response.get("security_plugin_available", False)
        admin_enabled = response.get("security_plugin_admin_enabled", False)
        message = response.get("message")
        if not available:
            if not message:
                print("Opensearch Security is not available for the service")
                return
            print(message)
            return
        if admin_enabled:
            print("Opensearch Security Management enabled")
            return
        print("Opensearch Security Management disabled")

    @arg.project
    @arg.service_name
    def service__opensearch_security_management__status(self) -> None:
        """Deprecated: Show status of the opensearch security"""
        print("Deprected: `use service opensearch security-management status` instead")
        self.service__opensearch__security_management__status()

    @arg.project
    @arg.service_name
    def service__opensearch__security_management__set(self) -> None:
        """Set the password for the opensearch security management"""
        print("Opensearch Security Management is enabled by setting the password")
        print("for the security management user. Once enabled normal Aiven service")
        print("user and ACL management is no longer used and all user and access control")
        print("can only be done using the native Opensearch Security API or dashboard.")
        if self.confirm("this action is unrevertable. Proceed (y/N)? "):
            passwd = self.enter_password(
                prompt="Setup Opensearch Security Manager",
                var="AIVEN_OS_SECOP_PASSWORD",
                confirm=True,
            )
            response = self.client.opensearch_security_set(
                project=self.get_project(),
                service=self.args.service_name,
                password=passwd,
            )
            print(response.get("message"))

    @arg.project
    @arg.service_name
    def service__opensearch_security_management__set(self) -> None:
        """Deprecated: Set the password for the opensearch security management"""
        print("Deprected: `use service opensearch security-management set` instead")
        self.service__opensearch__security_management__set()

    @arg.project
    @arg.service_name
    def service__opensearch__security_management__reset(self) -> None:
        """Reset the password for the opensearch security management"""
        old_passwd = self.enter_password(
            prompt="Old Opensearch Security Manager password",
            var="AIVEN_OS_SECOP_PASSWORD",
        )
        new_passwd = self.enter_password(
            prompt="New password",
            var="AIVEN_OS_SECOP_NEW_PASSWORD",
            confirm=True,
        )
        response = self.client.opensearch_security_reset(
            project=self.get_project(),
            service=self.args.service_name,
            old_password=old_passwd,
            new_password=new_passwd,
        )
        print(response.get("message"))

    @arg.project
    @arg.service_name
    def service__opensearch_security_management__reset(self) -> None:
        """Deprecated: Reset the password for the opensearch security management"""
        print("Deprected: `use service opensearch security-management reset` instead")
        self.service__opensearch__security_management__reset()


class AivenOpenSearchCLI(AivenOpenSearchSecurityCLI):
    pass
