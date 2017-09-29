Aiven Client |BuildStatus|_
===========================

.. |BuildStatus| image:: https://travis-ci.org/aiven/aiven-client.png?branch=master
.. _BuildStatus: https://travis-ci.org/aiven/aiven-client

Aiven is a next-generation managed cloud services platform.  Its focus is in
ease of adoption, high fault resilience, customer's peace of mind and
advanced features at competetive price points.  See https://aiven.io/ for
more information about the backend service.

aiven-client (`avn`) is the official command-line client for Aiven.

::

                        `'+;`         `'+;`
    The Aiven Crab    '@@@#@@@`     '@@@#@@@`
    ~~~~~~~~~~~~~~   #@.     #@.   @@.     #@.
                     @: ,@@   @@   @: ,@@   @@
                    ,@  @@@@@ :@  :@  @@@@@ .@
                     @  #@@@. #@   @` #@@@` @@
                     @@      `@#   @@      `@#
                      @@#. :@@+     @@#. :@@#
                       `+@@@'        `#@@@'
               ,;:`                             ,;;.
             @@@@@@#     .+@@@@@@@@@@@@@'.    `@@@@@@@
            @@@@@#    @@@@@@@@@@@@@@@@@@@@@@+    @@@@@@
             @@@   ;@@@@@@@@@@@@@@@@@@@@@@@@@@@`  `@@;
              `  `@@@@@@@@@@@        ;@@@@@@@@@@@
          `@@@  '@@@@@@@@@@@@@       @@@@@@@@@@@@@`  @@@
         '@@@` .@@@@@@@@@@@@@@@    `@@@@@@@@@@@@@@@  @@@@`
         @@@@  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  @@@@
        '@@@@  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  @@@@
        ,:::;  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  ,:::
           :@  ,@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  #@
           @@@  +@#+#@@@@@@@@@@@@@@@@@@@@@@@@@#+#@.  @@@
           @@@@        '@@@@@@@@@@@@@@@@@@@.        @@@@
           @@@  @@@@@@+  @@@@@@@@@@@@@@@@@  @@@@@@;  @@@
           @@  @@@@@@@@@  @@@@@@@@@@@@@@@ `@@@@@@@@@  @+
              @@@@@@@@@@@ :@@@@@@@@@@@@@  @@@@@@@@@@@ '
             `@@@@@@@@@@@       ```      ,@@@@@@@@@@@
             `@@@@@@   '@                :@:   @@@@@@
              @@@@@:                           @@@@@@
               @@@@@                           @@@@@
                @@@@#                         @@@@'

Platform requirements
=====================

Aiven Client has been tested and developed on Linux and Mac OS X systems.
It is a Python program that works with Python 2.7 or 3.4 or newer versions.
The only external dependency is Requests_ (and certifi_ on Windows/OSX).

.. _`Requests`: http://www.python-requests.org/
.. _`certifi`: https://certifi.io/

Installation
============

From PyPI (Linux/OSX)::

  $ python -m pip install aiven-client

From PyPI (Windows)::

  c:\> python -m pip install aiven-client

Build an RPM package (Linux)::

  $ make rpm

Basic Usage
===========
* NOTE: On Windows you may need to use ``python -m aiven.client`` instead of
``avn``.
* All commands will output the raw REST API JSON response with ``--json``

Login and users
---------------
Login::

  $ avn user login <your@email>

Expire all authentication tokens for your user, logs out all web console sessions, etc.
You will need to login again after this.::

 $ avn user tokens-expire

Clouds
------
List available cloud regions::

  $ avn cloud list

Projects
--------
List projects you are a member of::

  $ avn project list

Project commands operate on the currently active project or the project
specified with the `--project NAME` switch. The active project cab be changed
with the `switch` command::

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

  $ avn project user-invite somebody@aiven.io

Remove a user from the project::

  $ avn project user-remove somebody@aiven.io

View project management event log::

  $ avn events

View project service log entries::

  $ avn logs -n 100

Services
--------
List services (of the active project)::

  $ avn service list

List services in a specific project::

  $ avn service list --project proj2

List only a specific service::

  $ avn service list db1

Verbose list (includes connection information, etc.)::

  $ avn service list db1 -v

Full service information in json, as it is returned by the Aiven REST API::

  $ avn service list db1 --json

Only a specific field in the output, custom formatting::

  $ avn service list db1 --format "The service is at {service_uri}"

Launching services
------------------
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

Update a service to a different plan AND move it to another cloud region::

  $ avn service update mydb --plan startup-4 --cloud aws-us-east-1

Power off a service::

  $ avn service update mydb --power-off

Power on a service::

  $ avn service update mydb --power-on

Terminate a service (all data will be gone!)::

  $ avn service terminate mydb

Updating service configuration
------------------------------

More help
---------
::

  $ avn -h
  $ avn user -h
  $ avn service -h
  $ avn service create -h
  $ avn project -h

License
=======

Aiven Client is released under the Apache License, Version 2.0.

For the exact license terms, see `LICENSE` and
http://opensource.org/licenses/Apache-2.0 .

Contact
=======

Bug reports and patches are very welcome, please post them as GitHub issues
and pull requests at https://github.com/aiven/aiven-client
