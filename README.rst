Aiven Client |BuildStatus|_
###########################

.. |BuildStatus| image:: https://github.com/aiven/aiven-client/workflows/Build%20Aiven%20Client/badge.svg?branch=main
.. _BuildStatus: https://github.com/aiven/aiven-client/actions

Aiven is a next-generation managed cloud services platform.  Its focus is in
ease of adoption, high fault resilience, customer's peace of mind and
advanced features at competitive price points.  See https://aiven.io/ for
more information about the backend service.

aiven-client (``avn``) is the official command-line client for Aiven.

.. contents::


.. _platform-requirements:

Getting Started
===============

Requirements:

*  Python 3.8 or later

*  Requests_

*  For Windows and OSX, certifi_ is also needed

.. _`Requests`: http://www.python-requests.org/
.. _`certifi`: https://github.com/certifi/python-certifi

.. _installation:

Install from PyPi
-----------------

Pypi installation is the recommended route for most users::

  $ python3 -m pip install aiven-client


Build an RPM Package
--------------------

It is also possible to build an RPM::

  $ make rpm

Check Installation
------------------

To check that the tool is installed and working, run it without arguments::

  $ avn

If you see usage output, you're all set.

  **Note:** On Windows you may need to use ``python3 -m aiven.client`` instead of ``avn``.

Log In
------

The simplest way to use Aiven CLI is to authenticate with the username and
password you use on Aiven::

  $ avn user login <you@example.com>

The command will prompt you for your password.

You can also use an access token generated in the Aiven Console::

  $ avn user login <you@example.com> --token

You will be prompted for your access token as above.

If you are registered on Aiven through the AWS or GCP marketplace, then you need to specify an additional argument ``--tenant``. Currently the supported value are ``aws`` and ``gcp``, for example::

  $ avn user login <you@example.com> --tenant aws

.. _help-command:
.. _basic-usage:

Usage
=====

Some handy hints that work with all commands:

*  The ``avn help`` command shows all commands and can *search* for a command,
   so for example ``avn help kafka topic`` shows commands with kafka *and*
   topic in their description.

*  Passing ``-h`` or ``--help`` gives help output for any command. Examples:
   ``avn --help`` or ``avn service --help``.

*  All commands will output the raw REST API JSON response with ``--json``,
   we use this extensively ourselves in conjunction with
   `jq <https://stedolan.github.io/jq/>`__.


.. _login-and-users:

Authenticate: Logins and Tokens
-------------------------------

Login::

  $ avn user login <you@example.com>

Logout (revokes current access token, other sessions remain valid)::

  $ avn user logout

Expire all authentication tokens for your user, logs out all web console sessions, etc.
You will need to login again after this::

 $ avn user tokens-expire

Manage individual access tokens::

 $ avn user access-token list
 $ avn user access-token create --description <usage_description> [--max-age-seconds <secs>] [--extend-when-used]
 $ avn user access-token update <token|token_prefix> --description <new_description>
 $ avn user access-token revoke <token|token_prefix>

Note that the system has hard limits for the number of tokens you can create. If you're
permanently done using a token you should always use ``user access-token revoke`` operation
to revoke the token so that it does not count towards the quota.

Alternatively, you can add 2 JSON files, first create a default config in ``~/.config/aiven/aiven-credentials.json`` containing the JSON with an ``auth_token``::

  {
      "auth_token": "ABC1+123...TOKEN==",
      "user_email": "you@example.com"
  }

Second create a default config in ``~/.config/aiven/aiven-client.json`` containing the json with the ``default_project``::

  {"default_project": "yourproject-abcd"}

.. _clouds:

Choose your Cloud
-----------------

List available cloud regions::

  $ avn cloud list

.. _projects:

Working with Projects
---------------------

List projects you are a member of::

  $ avn project list

Project commands operate on the currently active project or the project
specified with the ``--project NAME`` switch. The active project cab be changed
with the ``project switch`` command::

  $ avn project switch <projectname>

Show active project's details::

  $ avn project details

Create a project and set the default cloud region for it::

  $ avn project create myproject --cloud aws-us-east-1

Delete an empty project::

  $ avn project delete myproject

List authorized users in a project::

  $ avn project user-list

Invite an existing Aiven user to a project::

  $ avn project user-invite somebody@example.com

Remove a user from the project::

  $ avn project user-remove somebody@example.com

View project management event log::

  $ avn events

.. _services:

Working with Permissions
------------------------

List organization permissions for a given resource type (one of "organization", "organization_unit", or "project")::

  $ avn permissions list --organization <organization_id> --resource-type <resource_type>

Set permissions for a given principal in the scope of resource type and resource ID::

  $ avn permissions set --organization <organization_id> --resource-type <resource_type> --resource-id <resource_id> --principal-id <principal_id> --principal-type <principal_type> --permission <permission1> --permission <permission2>

Note that setting permissions will override any existing permissions for the specified resource type and resource ID.

For example the following commands will set the permissions for the project with ID "proj1" to assign role "developer" to the user with ID "user1", and let them to be an "operator" for project "proj2"::

  $ avn permissions set --organization <organization_id> --resource-type project --resource-id proj1 --permission developer --principal-id user1 --principal-type user
  $ avn permissions set --organization <organization_id> --resource-type project --resource-id proj2 --permission operator --principal-id user1 --principal-type user

Explore Existing Services
-------------------------

List services (of the active project)::

  $ avn service list

List services in a specific project::

  $ avn service list --project proj2

List only a specific service::

  $ avn service list db1

Verbose list (includes connection information, etc.)::

  $ avn service list db1 -v

Full service information in JSON, as it is returned by the Aiven REST API::

  $ avn service list db1 --json

Only a specific field in the output, custom formatting::

  $ avn service list db1 --format "The service is at {service_uri}"

View service log entries (most recent entries and keep on following logs, other options can be used to get history)::

  $ avn service logs db1 -f

.. _launching-services:

Launch Services
---------------

View available service plans::

  $ avn service plans

Launch a PostgreSQL service::

  $ avn service create mydb -t pg --plan hobbyist

View service type specific options, including examples on how to set them::

  $ avn service types -v

Launch a PostgreSQL service of a specific version (see above command)::

  $ avn service create mydb96 -t pg --plan hobbyist -c pg_version=9.6

Update a service's list of allowed client IP addresses. Note that a list of multiple
values is provided as a comma separated list::

  $ avn service update mydb96 -c ip_filter=10.0.1.0/24,10.0.2.0/24,1.2.3.4/32

Open psql client and connect to the PostgreSQL service (also available for InfluxDB)::

  $ avn service cli mydb96

Update a service to a different plan AND move it to another cloud region::

  $ avn service update mydb --plan startup-4 --cloud aws-us-east-1

Power off a service::

  $ avn service update mydb --power-off

Power on a service::

  $ avn service update mydb --power-on

Terminate a service (all data will be gone!)::

  $ avn service terminate mydb

Managing service users
----------------------

Some service types support multiple users (e.g. PostgreSQL database users).

List, add and delete service users::

  $ avn service user-list
  $ avn service user-create
  $ avn service user-delete

For Valkey services it's possible to create users with ACLs_::

  $ avn service user-create --username new_user --valkey-acl-keys="prefix* another_key" --valkey-acl-commands="+set" --valkey-acl-categories="-@all +@admin" --valkey-acl-channels="prefix* some_chan" my-valkey-service

.. _`ACLs`: https://valkey.io/docs/topics/acl

Service users are created with strong random passwords.

Service Integrations
--------------------
`Service integrations <https://aiven.io/service-integrations>`_ allow to link Aiven services to other Aiven services or to services
offered by other companies for example for logging. Some examples for various diffenent integrations:
`Google cloud logging`_, `AWS Cloudwatch logging`_, `Remote syslog integration`_ and `Getting started with Datadog`_.

.. _`Google cloud logging`: https://help.aiven.io/en/articles/4209837-sending-service-logs-to-google-cloud-logging
.. _`AWS Cloudwatch logging`: https://help.aiven.io/en/articles/4134821-sending-service-logs-to-aws-cloudwatch
.. _`Remote syslog integration`: https://help.aiven.io/en/articles/2933115-remote-syslog-integration
.. _`Getting started with Datadog`: https://help.aiven.io/en/articles/1759208-getting-started-with-datadog

List service integration endpoints::

    $ avn service integration-endpoint-list

List all available integration endpoint types for given project::

    $ avn service integration-endpoint-types-list --project <project>

Create a service integration endpoint::

    $ avn service integration-endpoint-create --project <project> --endpoint-type <endpoint type> --endpoint-name <endpoint name> --user-config-json <user configuration as json>
    $ avn service integration-endpoint-create --project <project> --endpoint-type <endpoint type> --endpoint-name <endpoint name> -c <KEY=VALUE type user configuration>

Update a service integration endpoint::

    $ avn service integration-endpoint-update --project <project> --user-config-json <user configuration as json> <endpoint id>
    $ avn service integration-endpoint-update --project <project> -c <KEY=VALUE type user configuration> <endpoint id>

Delete a service integration endpoint::

    $ avn service integration-endpoint-delete --project <project>  <endpoint_id>

List service integrations::

    $ avn service integration-list <service name>

List all available integration types for given project::

    $ avn service integration-types-list --project <project>

Create a service integration::

    $ avn service integration-create --project <project> -t <integration type> -s <source service> -d <dest service> -S <source endpoint id> -D <destination endpoint id> --user-config-json <user configuration as json>
    $ avn service integration-create --project <project> -t <integration type> -s <source service> -d <dest service> -S <source endpoint id> -D <destination endpoint id> -c <KEY=VALUE type user configuration>

Update a service integration::

    $ avn service integration-update --project <project> --user-config-json <user configuration as json> <integration_id>
    $ avn service integration-update --project <project> -c <KEY=VALUE type user configuration> <integration_id>

Delete a service integration::

    $ avn service integration-delete --project <project> <integration_id>

Custom Files
------------

Listing files::

    $ avn service custom-file list --project <project> <service_name>

Reading file::

    $ avn service custom-file get --project <project> --file_id <file_id> [--target_filepath <file_path>] [--stdout_write] <service_name>


Uploading new files::

    $ avn service custom-file upload --project <project> --file_type <file_type> --file_path <file_path> --file_name <file_name> <service_name>

Updating existing files::

    $ avn service custom-file update --project <project> --file_path <file_path> --file_id <file_id> <service_name>

.. _teams:

Working with Teams
------------------

List account teams::

  $ avn account team list <account_id>

Create a team::

  $ avn account team create --team-name <team_name> <account_id>

Delete a team::

  $ avn account team delete --team-id <team_id> <account_id>

Attach team to a project::

  $ avn account team project-attach --team-id <team_id> --project <project_name> <account_id> --team-type <admin|developer|operator|read_only>


Detach team from project::

  $ avn account team project-detach --team-id <team_id> --project <project_name> <account_id>

List projects associated to the team::

  $ avn account team project-list --team-id <team_id> <account_id>

List members of the team::

  $ avn account team user-list --team-id <team_id> <account_id>

Invite a new member to the team::

  $ avn account team user-invite --team-id <team_id> <account_id> <somebody@example.com>

See the list of pending invitations::

  $ avn account team user-list-pending --team-id <team_id> <account_id>

Remove user from the team::

  $ avn account team user-delete --team-id <team_id> --user-id <user_id> <account_id>


.. _oauth2-clients:

Configuring OAuth2 Clients
--------------------------

List configured OAuth2 clients::

  $ avn account oauth2-client list <account_id>

Get a configured OAuth2 client's configuration::

  $ avn account oauth2-client list <account_id> --oauth2-client-id <client_id>

Create a new OAuth2 client information::

  $ avn account oauth2-client create <account_id> --name <app_name> -d <app_description> --redirect-uri <redirect_uri>

Delete an OAuth2 client::

  $ avn account oauth2-client delete <account_id> --oauth2-client-id <client_id>

List an OAuth2 client's redirect URIs::

  $ avn account oauth2-client redirect-list <account_id> --oauth2-client-id <client_id>

Create a new OAuth2 client redirect URI::

  $ avn account oauth2-client redirect-create <account_id> --oauth2-client-id <client_id> --redirect-uri <redirect_uri>

Delete an OAuth2 client redirect URI::

  $ avn account oauth2-client redirect-delete <account_id> --oauth2-client-id <client_id> --redirect-uri-id <redirect_uri_id>

List an OAuth2 client's secrets::

  $ avn account oauth2-client secret-list <account_id> --oauth2-client-id <client_id>

Create a new OAUth2 client secret::

  $ avn account oauth2-client secret-create <account_id> --oauth2-client-id <client_id>

Delete an OAuth2 client's secret::

  $ avn account oauth2-client secret-delete <account_id> --oauth2-client-id <client_id> --secret-id <secret_id>


Extra Features
==============

.. _shell-completions:

Autocomplete
------------

avn supports shell completions. It requires an optional dependency: argcomplete. Install it::

  $ python3 -m pip install argcomplete

To use completions in bash, add following line to ``~/.bashrc``::

  eval "$(register-python-argcomplete avn)"

For more information (including completions usage in other shells) see https://kislyuk.github.io/argcomplete/.

Auth Helpers
------------

When you spin up a new service, you'll want to connect to it. The ``--json`` option combined with the `jq <https://stedolan.github.io/jq/>`_ utility is a good way to grab the fields you need for your specific service. Try this to get the connection string::

  $ avn service get --json <service> | jq ".service_uri"

Each project has its own CA cert, and other services (notably Kafka) use mutualTLS so you will also need the ``service.key`` and ``service.cert`` files too for those. Download all three files to the local directory::

  $ avn service user-creds-download --username avnadmin <service>

For working with `kcat <https://github.com/edenhill/kcat>`_ (see also our `help article <https://developer.aiven.io/docs/products/kafka/howto/kcat.html>`_ ) or the command-line tools that ship with Kafka itself, a keystore and trustore are needed. By specifying which user's creds to use, and a secret, you can generate these via ``avn`` too::

  $ avn service user-kafka-java-creds --username avnadmin -p t0pS3cr3t <service>

Contributing
============

Check the `CONTRIBUTING <https://github.com/aiven/aiven-client/blob/main/.github/CONTRIBUTING.md>`_ guide for details on how to contribute to this repository.

Keep Reading
============

We maintain some other resources that you may also find useful:

* `Command Line Magic with avn <https://aiven.io/blog/command-line-magic-with-the-aiven-cli>`__
* `Managing Billing Groups via CLI <https://help.aiven.io/en/articles/4720981-using-billing-groups-via-cli>`__
