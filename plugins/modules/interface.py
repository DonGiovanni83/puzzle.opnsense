#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Kilian Soltermann <soltermann@puzzle.ch>, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""interface module: Module to configure OPNsense interface settings"""

# pylint: disable=duplicate-code
__metaclass__ = type

# https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_documenting.html
# fmt: off
DOCUMENTATION = r'''
---
author:
  - Fabio Bertagna (@dongiovanni83)
module: interface
version_added: "1.1.0"
short_description: This module can be used to assign interfaces to network ports and network IDs to new interfaces.
description:
  - Module to assign interfaces to network ports and network IDs to new interfaces.
options:
  identifier:
    description:
      - "Technical identifier of the interface, used by hasync for example"
    type: str
    required: true
  device:
    description:
      - Physical Device Name eg. vtnet0, ipsec1000 etc,.
    type: str
    required: true
  description:
    description:
      - Interface name shown in the GUI. Identifier in capital letters if not provided.
      - Input will be trimmed, as no whitespaces are allowed.
    type: str
    required: false
  enabled:
    description:
      - Enable or disable the interface
    type: bool
    required: false
    default: false
  locked:
    description:
      - Prevent interface removal
    type: bool
    required: false
  block_private:
    description:
        - When set, this option blocks traffic from IP addresses that are reserved for private networks as per RFC 1918 (10/8, 172.16/12, 192.168/16) as well as loopback addresses (127/8) and Carrier-grade NAT addresses (100.64/10). This option should only be set for WAN interfaces that use the public IP address space.
      type: bool
      required: false
  block_bogons:
    description:
        - When set, this option blocks traffic from IP addresses that are reserved (but not RFC 1918) or not yet assigned by IANA. Bogons are prefixes that should never appear in the Internet routing table, and obviously should not appear as the source address in any packets you receive.
      type: bool
      required: false
'''

EXAMPLES = r'''
- name: Assign Vagrant interface to device em4
  puzzle.opnsense.interface:
    identifier: "VAGRANT"
    device: "em4"

- name: Create new config
  puzzle.opnsense.interface:
    identifier: "lan"
    enabled: true
    device: "vtnet1"
    description: "lan_interface"
    block_bogons: true
'''

RETURN = '''
opnsense_configure_output:
    description: A list of the executed OPNsense configure function along with their respective stdout, stderr and rc
    returned: always
    type: list
    sample:
      - function: filter_configure
        params:
          - 'true'
        rc: 0
        stderr: ''
        stderr_lines: []
        stdout: ''
        stdout_lines: []

      - function: rrd_configure
        params:
          - 'true'
        rc: 0
        stderr: ''
        stderr_lines: []
        stdout: Generating RRD graphs...done.
        stdout_lines:
          - Generating RRD graphs...done.
'''
# fmt: on

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.puzzle.opnsense.plugins.module_utils.interface_utils import (
    InterfacesSet,
    InterfaceConfig,
    OPNSenseDeviceNotFoundError,
    OPNSenseDeviceAlreadyAssignedError,
    OPNSenseGetInterfacesError,
)


def main():
    """
    Main function of the interface module
    """

    module_args = {
        "identifier": {"type": "str", "required": True},
        "device": {"type": "str", "required": True},
        "description": {"type": "str", "required": False},
        "enabled": {"type": "bool", "required": False, "default": False},
        "locked": {"type": "bool", "required": False, "default": False},
        "block_private": {"type": "bool", "required": False, "default": False},
        "block_bogons": {"type": "bool", "required": False, "default": False}
    }

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        required_one_of=[
            ["identifier", "device", "description"],
        ],
    )

    # https://docs.ansible.com/ansible/latest/reference_appendices/common_return_values.html
    # https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_documenting.html#return-block
    result = {
        "changed": False,
        "invocation": module.params,
        "diff": None,
    }

    interface_config = InterfaceConfig.from_ansible_module_params(module.params)

    with InterfacesSet() as interfaces_set:

        try:
            interfaces_set.update(interface_config)

        except (
            OPNSenseDeviceNotFoundError
        ) as opnsense_device_not_found_error_error_message:
            module.fail_json(msg=str(opnsense_device_not_found_error_error_message))

        except (
            OPNSenseDeviceAlreadyAssignedError
        ) as opnsense_device_already_assigned_error_message:
            module.fail_json(msg=str(opnsense_device_already_assigned_error_message))

        except OPNSenseGetInterfacesError as opnsense_get_interfaces_error_message:
            module.fail_json(msg=str(opnsense_get_interfaces_error_message))

        if interfaces_set.changed:
            result["diff"] = interfaces_set.diff
            result["changed"] = True

        if interfaces_set.changed and not module.check_mode:
            interfaces_set.save()
            result["opnsense_configure_output"] = interfaces_set.apply_settings()

            for cmd_result in result["opnsense_configure_output"]:
                if cmd_result["rc"] != 0:
                    module.fail_json(
                        msg="Apply of the OPNsense settings failed",
                        details=cmd_result,
                    )

        # Return results
        module.exit_json(**result)


if __name__ == "__main__":
    main()
