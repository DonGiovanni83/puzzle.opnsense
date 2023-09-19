
# Copyright: (c) 2023, Reto Kupferschmid <kupferschmid@puzzle.ch>, Puzzle ITC
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Utilities used to apply OPNsense System -> Settings -> General config changes"""

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

from typing import List

from ansible_collections.puzzle.opnsense.plugins.module_utils import opnsense_utils

def apply() -> List[str]:
    """
    Execute the required php function to apply settings in the System -> Settings -> General (system_general.php) view.
    https://github.com/opnsense/core/blob/cbaf7cee1f0a6fabd1ec4c752a5d169c402976dc/src/www/system_general.php#L227

    :return: Returns a list os strings containing the stdout of all the commands executed
    """

    # requirements to execute the various functions can be found in the respective php file
    # https://github.com/opnsense/core/blob/cbaf7cee1f0a6fabd1ec4c752a5d169c402976dc/src/www/system_general.php#L30
    php_requirements = [
        "/usr/local/etc/inc/config.inc",
        "/usr/local/etc/inc/util.inc",
        "/usr/local/etc/inc/system.inc",
        "/usr/local/etc/inc/interfaces.lib.inc",
        "/usr/local/etc/inc/interfaces.inc",
        "/usr/local/etc/inc/filter.inc",
    ]

    cmd_output = []
    # the order of commands executed is relevant
    # https://github.com/opnsense/core/blob/cbaf7cee1f0a6fabd1ec4c752a5d169c402976dc/src/www/system_general.php#L227

    # https://github.com/opnsense/core/blob/cbaf7cee1f0a6fabd1ec4c752a5d169c402976dc/src/etc/inc/system.inc#L935
    cmd_output.append(
        opnsense_utils.run_function(
            php_requirements=php_requirements,
            configure_function="system_timezone_configure",
            configure_params=["true"], # first param: verbose
        )
    )

    # https://github.com/opnsense/core/blob/cbaf7cee1f0a6fabd1ec4c752a5d169c402976dc/src/etc/inc/system.inc#L864
    cmd_output.append(
        opnsense_utils.run_function(
            php_requirements=php_requirements,
            configure_function="system_trust_configure",
            configure_params=["true"], # first param: verbose
        )
    )

    # https://github.com/opnsense/core/blob/cbaf7cee1f0a6fabd1ec4c752a5d169c402976dc/src/etc/inc/system.inc#L864
    cmd_output.append(
        opnsense_utils.run_function(
            php_requirements=php_requirements,
            configure_function="system_hostname_configure",
            configure_params=["true"], # first param: verbose
        )
    )

    # https://github.com/opnsense/core/blob/cbaf7cee1f0a6fabd1ec4c752a5d169c402976dc/src/etc/inc/system.inc#L506
    cmd_output.append(
        opnsense_utils.run_function(
            php_requirements=php_requirements,
            configure_function="system_resolver_configure",
            configure_params=["true"], # first param: verbose
        )
    )

    # https://github.com/opnsense/core/blob/cbaf7cee1f0a6fabd1ec4c752a5d169c402976dc/src/etc/inc/plugins.inc#L251
    cmd_output.append(
        opnsense_utils.run_function(
            php_requirements=php_requirements,
            configure_function="plugins_configure",
            configure_params=["'dns'", "true"], # first param: hook, second param: verbose
        )
    )

    # https://github.com/opnsense/core/blob/cbaf7cee1f0a6fabd1ec4c752a5d169c402976dc/src/etc/inc/plugins.inc#L251
    cmd_output.append(
        opnsense_utils.run_function(
            php_requirements=php_requirements,
            configure_function="plugins_configure",
            configure_params=["'dhcp'", "true"], # first param: hook, second param: verbose
        )
    )

    # https://github.com/opnsense/core/blob/cbaf7cee1f0a6fabd1ec4c752a5d169c402976dc/src/etc/inc/filter.inc#L125
    cmd_output.append(
        opnsense_utils.run_function(
            php_requirements=php_requirements,
            configure_function="filter_configure",
            configure_params=["true"], # first param: verbose
        )
    )
    return cmd_output
