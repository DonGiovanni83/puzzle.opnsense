#  Copyright: (c) 2024, Puzzle ITC, Kilian Soltermann <soltermann@puzzle.ch>
#  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
interfaces_assignments_utils module_utils: Module_utils to configure OPNsense interface settings
"""
from dataclasses import dataclass
from typing import List, Optional, Dict
from xml.etree.ElementTree import Element, ElementTree

from ansible_collections.puzzle.opnsense.plugins.module_utils import (
    opnsense_utils,
)
from ansible_collections.puzzle.opnsense.plugins.module_utils.config_utils import (
    OPNsenseModuleConfig, ConfigObject
)


class OPNSenseDeviceNotFoundError(Exception):
    """
    Exception raised when a Device is not found.
    """


class OPNSenseDeviceAlreadyAssignedError(Exception):
    """
    Exception raised when a Device is already assigned to an Interface
    """


class OPNSenseGetInterfacesError(Exception):
    """
    Exception raised if the function can't query the local device
    """


@dataclass
class InterfaceAssignment(ConfigObject):
    """
    Represents a network interface with optional description and extra attributes.

    Attributes:
        identifier (str): Unique ID for the interface.
        device (str): Device name.
        descr (Optional[str]): Description of the interface.
        extra_attrs (Dict[str, Any]): Additional attributes for configuration.

    Methods:
        __init__: Initializes with ID, device, and optional description.
        from_xml: Creates an instance from XML.
        to_etree: Serializes instance to XML, handling special cases.
        from_ansible_module_params: Creates from Ansible params.
    """

    device: str
    descr: Optional[str] = None

    @classmethod
    def preprocess_ansible_module_params(cls, raw_params: dict) -> dict:
        """Preprocess params from Ansible module for TestConfigObject"""
        raw_params["_xml_tag"] = raw_params.pop("identifier")
        raw_params["descr"] = raw_params.pop("description", None)
        return raw_params

    @classmethod
    def preprocess_from_xml_data(cls, raw_xml_data: dict) -> dict:
        """Preprocess raw XML data for TestConfigObject instantiation"""

        params: dict = {**raw_xml_data}
        params["device"] = params.pop("if")
        return params

    def preprocess_instance_data_for_xml(self) -> dict:
        fields: dict = super().preprocess_instance_data_for_xml()
        fields["if"] = fields.pop("device")
        return fields


class InterfacesSet(OPNsenseModuleConfig):
    """
    Manages network interface assignments for OPNsense configurations.

    Inherits from OPNsenseModuleConfig, offering methods for managing
    interface assignments within an OPNsense config file.

    Attributes:
        _interfaces_assignments (List[InterfaceAssignment]): List of interface assignments.

    Methods:
        __init__(self, path="/conf/config.xml"): Initializes InterfacesSet and loads interfaces.
        _load_interfaces() -> List["Interface_assignment"]: Loads interface assignments from config.
        changed() -> bool: Checks if current assignments differ from the loaded ones.
        update(InterfaceAssignment: InterfaceAssignment): Updates an assignment,
        errors if not found.
        find(**kwargs) -> Optional[InterfaceAssignment]: Finds an assignment matching
        specified attributes.
        save() -> bool: Saves changes to the config file if there are modifications.
    """

    _interfaces_assignments: List[InterfaceAssignment]

    def __init__(self, path: str = "/conf/config.xml"):
        super().__init__(
            module_name="interfaces_assignments",
            config_context_names=["interfaces_assignments"],
            path=path,
        )

        self._config_xml_tree = self._load_config()
        self._interfaces_assignments = self._load_interfaces()

    def _load_interfaces(self) -> List["InterfaceAssignment"]:

        element_tree_interfaces: Element = self.get("interfaces")

        return [
            InterfaceAssignment.from_xml_element(element_tree_interface)
            for element_tree_interface in element_tree_interfaces
        ]

    @property
    def changed(self) -> bool:
        """
        Evaluates whether there have been changes to user or group configurations that are not yet
        reflected in the saved system configuration. This property serves as a check to determine
        if updates have been made in memory to the user or group lists that differ from what is
        currently persisted in the system's configuration files.
            Returns:
            bool: True if there are changes to the user or group configurations that have not been
                persisted yet; False otherwise.
            The method works by comparing the current in-memory representations of users and groups
        against the versions loaded from the system's configuration files. A difference in these
        lists indicates that changes have been made in the session that have not been saved, thus
        prompting the need for a save operation to update the system configuration accordingly.
            Note:
            This property should be consulted before performing a save operation to avoid
            unnecessary writes to the system configuration when no changes have been made.
        """

        return bool(str(self._interfaces_assignments) != str(self._load_interfaces()))

    def get_interfaces(self) -> List[InterfaceAssignment]:
        """
        Retrieves a list of interface assignments from an OPNSense device via a PHP function.

        The function queries the device using specified PHP requirements and config functions.
        It processes the stdout, extracts interface data, and handles errors.

        Returns:
            list[InterfaceAssignment]: A list of interface assignments parsed
                                       from the PHP function's output.

        Raises:
            OPNSenseGetInterfacesError: If an error occurs during the retrieval
                                        or parsing process,
                                        or if no interfaces are found.
        """

        # load requirements
        php_requirements = self._config_maps["interfaces_assignments"][
            "php_requirements"
        ]
        php_command = """
                    /* get physical network interfaces */
                    foreach (get_interface_list() as $key => $item) {
                        echo $key.',';
                    }
                    /* get virtual network interfaces */
                    foreach (plugins_devices() as $item){
                        foreach ($item["names"] as $key => $if ) {
                            echo $key.',';
                        }
                    }
                    """

        # run php function
        result = opnsense_utils.run_command(
            php_requirements=php_requirements,
            command=php_command,
        )

        # check for stderr
        if result.get("stderr"):
            raise OPNSenseGetInterfacesError(
                "error encounterd while getting interfaces"
            )

        # parse list
        interface_list: list[str] = [
            item.strip()
            for item in result.get("stdout").split(",")
            if item.strip() and item.strip() != "None"
        ]

        # check parsed list length
        if len(interface_list) < 1:
            raise OPNSenseGetInterfacesError(
                "error encounterd while getting interfaces, less than one interface available"
            )

        return interface_list

    def update(self, interface_assignment: InterfaceAssignment) -> None:
        """
        Updates an interface assignment in the set.

        Checks for device existence and updates or raises errors accordingly.

        Args:
            interface_assignment (InterfaceAssignment): The interface assignment to update.

        Raises:
            OPNSenseDeviceNotFoundError: If device is not found.
        """

        device_list_set: set = set(  # pylint: disable=R1718
            [assignment.device for assignment in self._interfaces_assignments]
        )

        identifier_list_set: set = set(  # pylint: disable=R1718
            [assignment.xml_tag_name for assignment in self._interfaces_assignments]
        )

        device_interfaces_set: set = set(self.get_interfaces())

        free_interfaces = device_interfaces_set - device_list_set

        if interface_assignment.device not in device_interfaces_set:
            raise OPNSenseDeviceNotFoundError(
                "Device was not found on OPNsense Instance!"
            )

        interface_to_update: Optional[InterfaceAssignment] = next(
            (
                interface
                for interface in self._interfaces_assignments
                if interface.device == interface_assignment.device
                   or interface.identifier == interface_assignment.identifier
            ),
            None,
        )

        if not interface_to_update:
            interface_to_create: InterfaceAssignment = InterfaceAssignment(
                identifier=interface_assignment.identifier,
                device=interface_assignment.device,
                descr=interface_assignment.descr,
            )

            self._interfaces_assignments.append(interface_to_create)

            return

        if (
                interface_assignment.device in free_interfaces
                or interface_assignment.device == interface_to_update.device
        ):

            if interface_assignment.identifier in identifier_list_set:

                # Merge extra_attrs
                interface_assignment.extra_attrs.update(interface_to_update.extra_attrs)

                # Update the existing interface
                interface_to_update.__dict__.update(interface_assignment.__dict__)

            else:
                raise OPNSenseDeviceAlreadyAssignedError(
                    "This device is already assigned, please unassign this device first"
                )

        else:
            raise OPNSenseDeviceAlreadyAssignedError(
                "This device is already assigned, please unassign this device first"
            )

    def find(self, **kwargs) -> Optional[InterfaceAssignment]:
        """
        Searches for an interface assignment that matches given criteria.

        Iterates through the list of interface assignments, checking if each one
        matches all provided keyword arguments. If a match is found, returns the
        corresponding interface assignment. If no match is found, returns None.

        Args:
            **kwargs: Key-value pairs to match against attributes of interface assignments.

        Returns:
            Optional[InterfaceAssignment]: The first interface assignment that matches
            the criteria, or None if no match is found.
        """

        for interface_assignment in self._interfaces_assignments:
            match = all(
                getattr(interface_assignment, key, None) == value
                for key, value in kwargs.items()
            )
            if match:
                return interface_assignment
        return None

    def save(self) -> bool:
        """
        Saves the current state of interface assignments to the OPNsense configuration file.

        Checks if there have been changes to the interface assignments. If not, it
        returns False indicating no need to save. It then locates the parent element
        for interface assignments in the XML tree and replaces existing entries with
        the updated set from memory. After updating, it writes the new XML tree to
        the configuration file and reloads the configuration to reflect changes.

        Returns:
            bool: True if changes were saved successfully, False if no changes were detected.

        Note:
            This method assumes that 'parent_element' correctly refers to the container
            of interface elements within the configuration file.
        """

        if not self.changed:
            return False

        # Use 'find' to get the single parent element
        parent_element = self._config_xml_tree.find(
            self._config_maps["interfaces_assignments"]["interfaces"]
        )

        # Assuming 'parent_element' correctly refers to the container of interface elements
        for interface_element in list(parent_element):
            parent_element.remove(interface_element)

        # Now, add updated interface elements
        parent_element.extend(
            [
                interface_assignment.to_etree()
                for interface_assignment in self._interfaces_assignments
            ]
        )

        # Write the updated XML tree to the file
        tree = ElementTree(self._config_xml_tree)
        tree.write(self._config_path, encoding="utf-8", xml_declaration=True)

        return True
