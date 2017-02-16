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

Projects
--------
List projects::

  $ avn project list

Switch a project as the default one::

  $ avn project switch <projectname>

Create a project::

  $ avn project create myproject

Delete an empty project::

  $ avn project delete myproject

Show project details::

  $ avn project details

List authorized users in a project::

  $ avn project user-list

Invite an existing Aiven user to a project::

  $ avn project user-invite somebody@aiven.io

Remove a user from the project::

  $ avn project user-remove somebody@aiven.io

View project event log::

  $ avn events

View project log entries::

  $ avn logs -n 100

Services
--------
List services (of the default project)::

  $ avn service list

List services in a non-default project::

  $ avn service list --project proj2

Switch default project::

  $ avn project switch proj2

List only a specific service::

  $ avn project list db1

Verbose list (includes connection information, etc.)::

  $ avn project list db1 -v

Full service information in json, as it is returned by the Aiven REST API::

  $ avn project list db1 --json

Only a specific field in the output, custom formatting::

  $ avn project list db1 --format "The service is at {service_uri}"

Launching services
------------------
View available service plans::

  $ avn service plans

Launch a PostgreSQL service::

  $ avn service create mydb -t pg --plan hobbyist

View service-specific options::

  $ avn service types -v

Launch a PostgreSQL service of a specific version (see above command)::

  $ avn service create mydb96 -t pg --plan hobbyist -c pg_version=9.6

Update a service to a bigger plan AND move it to another cloud::

  $ avn service update mydb --plan startup-4 --cloud aws-us-east-1

Power off a service::

  $ avn service update mydb --power-off

Power on a service::

  $ avn service update mydb --power-on

Terminate a service (all data will be gone!)::

  $ avn service terminate mydb

Clouds
------
List available cloud regions::

  $ avn cloud list

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
