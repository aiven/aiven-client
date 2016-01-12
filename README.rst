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
NOTE: On Windows you may need to use ``python -m aiven.client`` instead of
``avn``.

Login::

  $ avn user login <your@email>

List projects::

  $ avn project list


Switch a project as the default one::

  $ avn project switch <projectname>

List services (of the default project)::

  $ avn service list -v

More help::

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
