#!/usr/bin/env python
"""Updates the Emerging Threats open ruleset for Suricata"""

"""Copyright 2015 Sean Whalen

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License."""

from sys import stdout
import logging
from urllib2 import Request, urlopen
from StringIO import StringIO
from hashlib import md5
from os import path
from tarfile import TarFile
from argparse import ArgumentParser

__author__ = "Sean Whalen"
__version__ = "0.7"
__license__ = "Apache 2.0"
name = "etupdate"

argparser = ArgumentParser(description=__doc__, version=__version__)
argparser.add_argument("--verbose", "-v", action="store_true", help="Output to the console")
argparser.add_argument("--force", "-f", action="store_true",
                       help="Download and install rules without checking for updates")

url_root = "http://rules.emergingthreats.net/open/suricata"
version_url = "{0}/version.txt".format(url_root)
rules_url = "{0}/emerging.rules.tar.gz".format(url_root)
hash_url = "{0}/emerging.rules.tar.gz.md5".format(url_root)
file_root = "/etc/suricata"
version_path = path.join(file_root, "rules", "eto_version")

logger = logging.getLogger(name)
logger.setLevel(logging.CRITICAL)
log_handler = logging.StreamHandler(stdout)
logger.addHandler(log_handler)


def request(url, binary=False):
    """Make a standardized HTTP GET request with the proper user agent.
Return the response as a string, or StringIO if it is a binary."""
    req = Request(url, headers={'User-Agent': '{0}/{1}'.format(name, __version__)})
    response = urlopen(req).read()
    if binary:
        response = StringIO(response)
    return response


def get_latest_version():
    """Returns the latest version number from the rules server as an int."""
    version = int(request(version_url))
    logger.info("Latest version: {0}".format(version))
    return version


def get_current_version():
    """Returns the current version number for the rules as an int, or 0 if no version information exists."""
    current_version = 0
    if path.exists(version_path):
        with open(version_path, mode="r") as version_file:
            current_version = int(version_file.read())
    logger.info("Current version: {0}".format(current_version))
    return current_version


def check_for_update():
    """Returns True if new rules are available."""
    return get_latest_version() > get_current_version()


def hash_file(file_object, hasher, block_size=65536):
    """Returns a hash digest of choice for a given file object."""
    buf = file_object.read(block_size)
    while len(buf) > 0:
        hasher.update(buf)
        buf = file_object.read(block_size)
    return hasher.hexdigest()


def download_rules():
    """Download the ruleset, and check its hash. Returns an open TarFile."""
    logger.info("Downloading rules...")
    remote_hash = request(hash_url).strip()
    rules_file = request(rules_url, binary=True)
    rules_hash = hash_file(rules_file, md5())
    if rules_hash != remote_hash:
        raise RuntimeError("The rules archive did not match its hash")
    rules_file.seek(0)
    return TarFile.open(fileobj=rules_file, mode="r:gz")


def check_archive_safety(archive):
    """Returns False is an archive has any evil paths members with names that start with .. or /"""
    safe = True
    for member in archive.members:
        if member.name.startswith("/") or member.name.startswith(".."):
            safe = False
            break
    if not safe:
        raise RuntimeError("The archive contained paths that are not safe")


def main():
    """Called when module is ran on its own"""
    args = argparser.parse_args()
    if args.verbose:
        logger.setLevel(logging.INFO)

    current_version = get_current_version()
    latest_version = get_latest_version()

    if args.force or (latest_version > current_version):
        rules = download_rules()
        check_archive_safety(rules)
        logger.info("Extracting rules to '{0}'...".format(file_root))
        rules.extractall(file_root)
        current_version = latest_version
        with open(version_path, "w") as version_file:
            version_file.write(str(current_version))

if __name__ == "__main__":
    main()
