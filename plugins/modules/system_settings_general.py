#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Reto Kupferschmid <kupferschmid@puzzle.ch>, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Example module: Show minimal functionality of OPNsenseConfig class"""

__metaclass__ = type

# https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_documenting.html
DOCUMENTATION = r"""
---
author:
- Reto Kupferschmid (@rekup)
module: system_settings_general
short_description: Configure general settings mainly concern network-related settings like the hostname.
description:
- Module to configure general system settings
options:
  hostname:
    description:
    - Hostname without domain, e.g.: V(firewall)
    type: str
    required: false
  domain:
    description:
    - The domain, e.g. V(mycorp.com), V(home), V(office), V(private), etc.
    - Do not use V(local)as a domain name. It will cause local hosts running mDNS (avahi, bonjour, etc.) to be unable to resolve local hosts not running mDNS.
    type: str
    required: false
"""

EXAMPLES = r"""
- name: Set hostname to opnsense
  puzzle.opnsense.system_settings_general:
    hostname: "opnsense"

- name: Set domain to mycorp.com
  puzzle.opnsense.system_settings_general:
    domain: mycorp.com
"""

RETURN = r""" # """

import re

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.puzzle.opnsense.plugins.module_utils import (
    config_utils,
    system_settings_general_utils,
)

HOSTNAME_INDEX = 1
DOMAIN_INDEX = 2

def get_hostname(settings):
    return settings[HOSTNAME_INDEX]


def get_domain(settings):
    return settings[DOMAIN_INDEX]


def is_hostname(hostname: str) -> bool:
    """
    Validates hostnames

    :param hostname: A string containing the hostname

    :return: True if the provided hostname is valid, False if it's invalid
    """

    # https://github.com/opnsense/core/blob/cbaf7cee1f0a6fabd1ec4c752a5d169c402976dc/src/etc/inc/util.inc#L704
    hostname_regex = r"^(?:(?:[a-z0-9_]|[a-z0-9_][a-z0-9_\-]*[a-z0-9_])\.)*(?:[a-z0-9_]|[a-z0-9_][a-z0-9_\-]*[a-z0-9_])$"
    return re.match(hostname_regex, hostname) is not None

def is_domain(domain: str) -> bool:
    """
    Validates domain

    :param hostname: A string containing the domain

    :return: True if the provided domain is valid, False if it's invalid
    """

    # https://github.com/opnsense/core/blob/cbaf7cee1f0a6fabd1ec4c752a5d169c402976dc/src/etc/inc/util.inc#L716
    domain_regex = r"^(?:(?:[a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\.)*(?:[a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])$"
    return re.match(domain_regex, domain) is not None

def main():
    """
    Main function of the system_settings_general module
    """

    module_args = dict(
        hostname=dict(type="str", required=False),
        domain=dict(type="str", required=False),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        required_one_of=[
            ["domain", "hostname"],
        ],
    )

    # https://docs.ansible.com/ansible/latest/reference_appendices/common_return_values.html
    # https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_documenting.html#return-block
    result = {
        "changed": False,
        "invocation": module.params,
        "msg": "",
    }

    hostname_param = module.params.get("hostname")
    domain_param = module.params.get("domain")

    with config_utils.OPNsenseConfig(check_mode=module.check_mode) as config_mgr:
        # Get system settings
        system_settings = config_mgr["system"]
        current_hostname = get_hostname(system_settings)
        current_domain = get_domain(system_settings)

        if hostname_param:
            if not is_hostname(hostname_param):
                module.fail_json(msg="Invalid hostname parameter specified")

            if hostname_param != current_hostname["hostname"]:
                current_hostname["hostname"] = hostname_param

        if domain_param:
            if not is_domain(domain_param):
                module.fail_json(msg="Invalid domain parameter specified")

            if domain_param != current_domain["domain"]:
                current_domain["domain"] = domain_param

        if config_mgr.changed:
            result["diff"] = config_mgr.diff
            result["changed"] = True

        if config_mgr.changed and not module.check_mode:
            config_mgr.save()
            result[
                "opnsense_configure_output"
            ] = system_settings_general_utils.apply()

    # Return results
    module.exit_json(**result)

if __name__ == "__main__":
    main()
