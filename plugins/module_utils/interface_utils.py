#  Copyright: (c) 2024, Puzzle ITC, Kilian Soltermann <soltermann@puzzle.ch>
#  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
interfaces_utils module_utils: Module_utils to configure OPNsense interface settings
"""

from dataclasses import dataclass, asdict, field
from typing import List, Optional, Dict, Any, Tuple


from xml.etree.ElementTree import Element, ElementTree, SubElement

from ansible_collections.puzzle.opnsense.plugins.module_utils import (
    xml_utils,
    opnsense_utils,
)
from ansible_collections.puzzle.opnsense.plugins.module_utils.config_utils import (
    OPNsenseModuleConfig,
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
class InterfaceConfig:
    """
    Represents a network interface with optional description and extra attributes.

    Attributes:
        identifier (str): Unique ID for the interface.
        device (str): Device name.
        descr (Optional[str]): Description of the interface.
        block_private (bool): When set, this option blocks traffic from IP addresses
            that are reserved for private networks as per RFC 1918 (10/8, 172.16/12, 192.168/16)
            as well as loopback addresses (127/8) and Carrier-grade NAT addresses (100.64/10).
            This option should only be set for WAN interfaces that use the public IP address space.
        block_bogons (bool):  When set, this option blocks traffic from IP addresses that are reserved
            (but not RFC 1918) or not yet assigned by IANA. Bogons are prefixes that should never appear
            in the Internet routing table, and obviously should not appear as the source address in any
            packets you receive.
        extra_attrs (Dict[str, Any]): Additional attributes for configuration.

    Methods:
        __init__: Initializes with ID, device, and optional description.
        from_xml: Creates an instance from XML.
        to_etree: Serializes instance to XML, handling special cases.
        from_ansible_module_params: Creates from Ansible params.
    """

    identifier: str
    device: str
    block_private: bool
    block_bogons: bool
    enabled: bool = False
    locked: bool = False
    descr: Optional[str] = None

    # since only the above attributes are needed, the rest is handled here
    extra_attrs: Dict[str, Any] = field(default_factory=dict, repr=False)

    def __init__(
        self,
        identifier: str,
        device: str,
        enabled: bool = False,
        locked: bool = False,
        block_private: bool = False,
        block_bogons: bool = False,
        descr: Optional[str] = None,
        **kwargs,
    ):
        self.identifier = identifier
        self.device = device
        self.block_private = block_private
        self.block_bogons = block_bogons
        self.enabled = enabled
        self.locked = locked
        if descr is not None:
            self.descr = descr
        self.extra_attrs = kwargs

    @staticmethod
    def from_xml(element: Element) -> "InterfaceConfig":
        """
        Converts XML element to InterfaceConfig instance.

        Args:
            element (Element): XML element representing an interface.

        Returns:
            InterfaceConfig: An instance with attributes derived from the XML.

        Processes XML to dict, assigning 'identifier' and 'device' from keys and
        'if' element. Assumes single key processing.
        """

        interface_config_dict: dict = xml_utils.etree_to_dict(element)

        for key, value in interface_config_dict.items():
            value["identifier"] = key  # Move the key to a new "identifier" field
            if "if" in value:
                if_key = value.pop("if", None)
                if if_key is not None:
                    value["device"] = if_key
                    
            mapped_fields: List[Tuple] = [
                ("enable", "enabled"),
                ("lock", "locked"),
                ("blockpriv", "block_private"),
                ("blockbogons", "block_bogons"),
            ]
            
            for xml_key, class_field in mapped_fields:
                if xml_key in value:
                    value[class_field] = bool(int(value.pop(xml_key, None)))
            
            break  # Only process the first key, assuming there's only one

        # Return only the content of the dictionary without the key
        return InterfaceConfig(**interface_config_dict.popitem()[1])

    def to_etree(self) -> Element:
        """
        Serializes the instance to an XML Element, including extra attributes.

        Returns:
            Element: XML representation of the instance.

        Creates an XML element with identifier, device, and description. Handles
        serialization of additional attributes, excluding specified exceptions and
        handling specific attribute cases like alias and DHCP options. Assumes
        boolean values translate to '1' for true.
        """

        interface_config_dict: dict = asdict(self)

        exceptions = ["dhcphostname", "mtu", "subnet", "gateway", "media", "mediaopt"]

        # Create the main element
        main_element = Element(interface_config_dict["identifier"])
        # Special handling for 'device' and 'descr'
        SubElement(main_element, "if").text = interface_config_dict.get("device")
        SubElement(main_element, "descr").text = interface_config_dict.get("descr")
        
        # Special handling for 'blockbogons' & 'blockpriv'
        mapped_fields: List[Tuple] = [
            ("blockpriv", "block_private"),
            ("blockbogons", "block_bogons"),
            ("enable", "enabled"),
            ("lock", "locked"),
        ]
        for xml_key, class_field in mapped_fields:
            if getattr(self, class_field):
                SubElement(main_element, xml_key).text = str(int(getattr(self, class_field)))

        # handle special cases
        if getattr(self, "alias-subnet", None):
            interface_config_dict["extra_attrs"]["alias-subnet"] = getattr(
                self, "alias-subnet", None
            )

            interface_config_dict["extra_attrs"]["alias-address"] = getattr(
                self, "alias-address", None
            )

        if getattr(self, "dhcp6-ia-pd-len", None):
            interface_config_dict["extra_attrs"]["dhcp6-ia-pd-len"] = getattr(
                self, "dhcp6-ia-pd-len", None
            )

        if getattr(self, "track6-interface", None):
            interface_config_dict["extra_attrs"]["track6-interface"] = getattr(
                self, "track6-interface", None
            )

        if getattr(self, "track6-prefix-id", None):
            interface_config_dict["extra_attrs"]["track6-prefix-id"] = getattr(
                self, "track6-prefix-id", None
            )

        # Serialize extra attributes
        for key, value in interface_config_dict["extra_attrs"].items():
            if (
                key
                in [
                    "spoofmac",
                    "alias-address",
                    "alias-subnet",
                    "dhcp6-ia-pd-len",
                    "adv_dhcp_pt_timeout",
                    "adv_dhcp_pt_retry",
                    "adv_dhcp_pt_select_timeout",
                    "adv_dhcp_pt_reboot",
                    "adv_dhcp_pt_backoff_cutoff",
                    "adv_dhcp_pt_initial_interval",
                    "adv_dhcp_pt_values",
                    "adv_dhcp_send_options",
                    "adv_dhcp_request_options",
                    "adv_dhcp_required_options",
                    "adv_dhcp_option_modifiers",
                    "adv_dhcp_config_advanced",
                    "adv_dhcp_config_file_override",
                    "adv_dhcp_config_file_override_path",
                    "dhcprejectfrom",
                    "track6-interface",
                    "track6-prefix-id",
                ]
                and value is None
            ):
                sub_element = SubElement(main_element, key)
            if value is None and key not in exceptions:
                continue
            sub_element = SubElement(main_element, key)
            if value is True:
                sub_element.text = "1"
            elif value is not None:
                sub_element.text = str(value)

        return main_element

    @classmethod
    def from_ansible_module_params(cls, params: dict) -> "InterfaceConfig":
        """
        Creates an instance from Ansible module parameters.

        Args:
            params (dict): Parameters from an Ansible module.

        Returns:
            User: An instance of InterfaceConfig.

        Filters out None values from the provided parameters and uses them to
        instantiate the class, focusing on 'identifier', 'device', and 'descr'.
        """

        interface_config_dict = {
            "identifier": params.get("identifier"),
            "device": params.get("device"),
            "descr": params.get("description"),
            "enabled": params.get("enabled"),
            "locked": params.get("locked"),
            "block_private": params.get("block_private", None),
            "block_bogons": params.get("block_bogons", None)
        }

        interface_config_dict = {
            key: value
            for key, value in interface_config_dict.items()
            if value is not None
        }

        return cls(**interface_config_dict)


class InterfacesSet(OPNsenseModuleConfig):
    """
    Manages network interface configs for OPNsense configurations.

    Inherits from OPNsenseModuleConfig, offering methods for managing
    interface configs within an OPNsense config file.

    Attributes:
        _interfaces_configs (List[InterfaceConfig]): List of interface configs.

    Methods:
        __init__(self, path="/conf/config.xml"): Initializes InterfacesSet and loads interfaces.
        _load_interfaces() -> List["InterfaceConfig"]: Loads interface configs from config.
        changed() -> bool: Checks if current configs differ from the loaded ones.
        update(InterfaceConfig: InterfaceConfig): Updates an config,
        errors if not found.
        find(**kwargs) -> Optional[InterfaceConfig]: Finds an config matching
        specified attributes.
        save() -> bool: Saves changes to the config file if there are modifications.
    """

    _interfaces_configs: List[InterfaceConfig]

    def __init__(self, path: str = "/conf/config.xml"):
        super().__init__(
            module_name="interface",
            config_context_names=["interface"],
            path=path,
        )

        self._config_xml_tree = self._load_config()
        self._interfaces_configs = self._load_interfaces()

    def _load_interfaces(self) -> List["InterfaceConfig"]:

        element_tree_interfaces: Element = self.get("interfaces")

        return [
            InterfaceConfig.from_xml(element_tree_interface)
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

        return bool(str(self._interfaces_configs) != str(self._load_interfaces()))

    def get_interfaces(self) -> List[InterfaceConfig]:
        """
        Retrieves a list of interface configs from an OPNSense device via a PHP function.

        The function queries the device using specified PHP requirements and config functions.
        It processes the stdout, extracts interface data, and handles errors.

        Returns:
            list[InterfaceConfig]: A list of interface configs parsed
                                       from the PHP function's output.

        Raises:
            OPNSenseGetInterfacesError: If an error occurs during the retrieval
                                        or parsing process,
                                        or if no interfaces are found.
        """

        # load requirements
        php_requirements = self._config_maps["interface"][
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

    def update(self, interface_config: InterfaceConfig) -> None:
        """
        Updates an interface config in the set.

        Checks for device existence and updates or raises errors accordingly.

        Args:
            interface_config (InterfaceConfig): The interface config to update.

        Raises:
            OPNSenseDeviceNotFoundError: If device is not found.
        """

        device_list_set: set = set(  # pylint: disable=R1718
            [config.device for config in self._interfaces_configs]
        )

        identifier_list_set: set = set(  # pylint: disable=R1718
            [config.identifier for config in self._interfaces_configs]
        )

        device_interfaces_set: set = set(self.get_interfaces())

        free_interfaces = device_interfaces_set - device_list_set

        if interface_config.device not in device_interfaces_set:
            raise OPNSenseDeviceNotFoundError(
                "Device was not found on OPNsense Instance!"
            )

        interface_to_update: Optional[InterfaceConfig] = next(
            (
                interface
                for interface in self._interfaces_configs
                if interface.device == interface_config.device
                or interface.identifier == interface_config.identifier
            ),
            None,
        )

        if not interface_to_update:

            interface_to_create: InterfaceConfig = InterfaceConfig(
                identifier=interface_config.identifier,
                device=interface_config.device,
                descr=interface_config.descr,
            )

            self._interfaces_configs.append(interface_to_create)

            return

        if (
            interface_config.device in free_interfaces
            or interface_config.device == interface_to_update.device
        ):

            if interface_config.identifier in identifier_list_set:

                # Merge extra_attrs
                interface_config.extra_attrs.update(interface_to_update.extra_attrs)

                # Update the existing interface
                interface_to_update.__dict__.update(interface_config.__dict__)

            else:
                raise OPNSenseDeviceAlreadyAssignedError(
                    "This device is already assigned, please unassign this device first"
                )

        else:
            raise OPNSenseDeviceAlreadyAssignedError(
                "This device is already assigned, please unassign this device first"
            )

    def find(self, **kwargs) -> Optional[InterfaceConfig]:
        """
        Searches for an interface config that matches given criteria.

        Iterates through the list of interface configs, checking if each one
        matches all provided keyword arguments. If a match is found, returns the
        corresponding interface config. If no match is found, returns None.

        Args:
            **kwargs: Key-value pairs to match against attributes of interface configs.

        Returns:
            Optional[InterfaceConfig]: The first interface config that matches
            the criteria, or None if no match is found.
        """

        for interface_config in self._interfaces_configs:
            match = all(
                getattr(interface_config, key, None) == value
                for key, value in kwargs.items()
            )
            if match:
                return interface_config
        return None

    def save(self) -> bool:
        """
        Saves the current state of interface configs to the OPNsense configuration file.

        Checks if there have been changes to the interface configs. If not, it
        returns False indicating no need to save. It then locates the parent element
        for interface configs in the XML tree and replaces existing entries with
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
            self._config_maps["interface"]["interfaces"]
        )

        # Assuming 'parent_element' correctly refers to the container of interface elements
        for interface_element in list(parent_element):
            parent_element.remove(interface_element)

        # Now, add updated interface elements
        parent_element.extend(
            [
                interface_config.to_etree()
                for interface_config in self._interfaces_configs
            ]
        )

        # Write the updated XML tree to the file
        tree = ElementTree(self._config_xml_tree)
        tree.write(self._config_path, encoding="utf-8", xml_declaration=True)

        return True
