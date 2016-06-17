# Copyright 2015, Aiven, https://aiven.io/
#
# This file is under the Apache License, Version 2.0.
# See the file `LICENSE` for details.

from .argx import arg
import os

arg.card_id = arg("--card-id", help="Card ID")
arg.cloud = arg("--cloud", help="Cloud to use (see 'cloud list' command)")
arg.email = arg("email", help="User email address")
arg.force = arg("-f", "--force", help="Force action without interactive confirmation",
                action="store_true", default=False)
arg.index_name = arg("index_name", help="Index name")
arg.json = arg("--json", help="Raw json output", action="store_true", default=False)
arg.partitions = arg("--partitions", type=int, help="Number of partitions")
arg.project = arg("--project", help="Project name to use, default %(default)r",
                  default=os.environ.get("AIVEN_PROJECT"))
arg.replication = arg("--replication", type=int, help="Replication factor")
arg.retention = arg("--retention", type=int, help="Retention period (hours)")
arg.service_name = arg("name", help="Service name")
arg.service_type = arg("-t", "--service-type", help="Type of service (see 'service list-types')")
arg.timeout = arg("--timeout", type=int, help="Wait for up to N seconds (default: infinite)")
arg.topic = arg("topic", help="Topic name")
arg.user_config = arg("-c", dest="user_config", action="append", default=[],
                      help="User configuration: KEY=JSON_VALUE")
arg.verbose = arg("-v", "--verbose", help="Verbose output", action="store_true", default=False)
