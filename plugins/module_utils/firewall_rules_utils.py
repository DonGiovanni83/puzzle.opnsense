#  Copyright: (c) 2023, Puzzle ITC, Fabio Bertagna <bertagna@puzzle.ch>
#  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
import enum
import logging
from dataclasses import dataclass, field, asdict, fields
from enum import Enum
from typing import List, Optional, Any
import uuid
from xml.etree.ElementTree import Element, ElementTree

from ansible_collections.puzzle.opnsense.plugins.module_utils import xml_utils
from ansible_collections.puzzle.opnsense.plugins.module_utils.config_utils import (
    OPNsenseModuleConfig,
)


class ListEnum(Enum):
    """Enum class with some handy utility functions."""

    @classmethod
    def as_list(cls) -> List[str]:
        """
        Return a list
        Returns
        -------

        """
        return [entry.value for entry in cls]

    @classmethod
    def from_string(cls, value: str) -> "ListEnum":
        """
        Returns Enum value, from a given String.
        If no enum value can be mapped to the input string,
        ValueError is raised.
        Parameters
        ----------
        value: `str`
            String to be mapped to enum value

        Returns
        -------
        Enum value
        """
        for _key, _value in cls.__members__.items():
            if value in (_key, _value.value):
                return _value
        raise ValueError(f"'{cls.__name__}' enum not found for '{value}'")


class FirewallRuleAction(ListEnum):
    """Represents the rule filter policy."""

    PASS = "pass"
    BLOCK = "block"
    REJECT = "reject"


class FirewallRuleDirection(ListEnum):
    """Represents the rule direction."""

    IN = "in"
    OUT = "out"


class FirewallRuleProtocol(ListEnum):
    """Represents the protocol to filter in a rule."""

    ANY = "any"
    TCP = "tcp"
    UDP = "udp"
    TCP_UDP = "tcp/udp"
    ICMP = "icmp"
    ESP = "esp"
    AH = "ah"
    GRE = "gre"
    IGMP = "igmp"
    PIM = "pim"
    OSPF = "ospf"
    GGP = "ggp"
    IPENCAP = "ipencap"
    ST2 = "st2"
    CBT = "cbt"
    EGP = "egp"
    IGP = "igp"
    BBN_RCC = "bbn-rcc"
    NVP = "nvp"
    PUP = "pup"
    ARGUS = "argus"
    EMCON = "emcon"
    XNET = "xnet"
    CHAOS = "chaos"
    MUX = "mux"
    DCN = "dcn"
    HMP = "hmp"
    PRM = "prm"
    XNS_IDP = "xns-idp"
    TRUNK_1 = "trunk-1"
    TRUNK_2 = "trunk-2"
    LEAF_1 = "leaf-1"
    LEAF_2 = "leaf-2"
    RDP = "rdp"
    IRTP = "irtp"
    ISO_TP4 = "iso-tp4"
    NETBLT = "netblt"
    MFE_NSP = "mfe-nsp"
    MERIT_INP = "merit-inp"
    DCCP = "dccp"
    PC = "3pc"
    IDPR = "idpr"
    XTP = "xtp"
    DDP = "ddp"
    IDPR_CMTP = "idpr-cmtp"
    TP_PLUS_PLUS = "tp++"
    IL = "il"
    IPV6 = "ipv6"
    SDRP = "sdrp"
    IDRP = "idrp"
    RSVP = "rsvp"
    DSR = "dsr"
    BNA = "bna"
    I_NLSP = "i-nlsp"
    SWIPE = "swipe"
    NARP = "narp"
    MOBILE = "mobile"
    TLSP = "tlsp"
    SKIP = "skip"
    IPV6_ICMP = "ipv6-icmp"
    CFTP = "cftp"
    SAT_EXPAK = "sat-expak"
    KRYPTOLAN = "kryptolan"
    RVD = "rvd"
    IPPC = "ippc"
    SAT_MON = "sat-mon"
    VISA = "visa"
    IPCV = "ipcv"
    CPNX = "cpnx"
    CPHB = "cphb"
    WSN = "wsn"
    PVP = "pvp"
    BR_SAT_MON = "br-sat-mon"
    SUN_ND = "sun-nd"
    WB_MON = "wb-mon"
    WB_EXPAK = "wb-expak"
    ISO_IP = "iso-ip"
    VMTP = "vmtp"
    SECURE_VMTP = "secure-vmtp"
    VINES = "vines"
    TTP = "ttp"
    NSFNET_IGP = "nsfnet-igp"
    DGP = "dgp"
    TCF = "tcf"
    EIGRP = "eigrp"
    SPRITE_RPC = "sprite-rpc"
    LARP = "larp"
    MTP = "mtp"
    AX_25 = "ax.25"
    IPIP = "ipip"
    MICP = "micp"
    SCC_SP = "scc-sp"
    ETHERIP = "etherip"
    ENCAP = "encap"
    GMTP = "gmtp"
    IFMP = "ifmp"
    PNNI = "pnni"
    ARIS = "aris"
    SCPS = "scps"
    QNX = "qnx"
    A_N = "a/n"
    IPCOMP = "ipcomp"
    SNP = "snp"
    COMPAQ_PEER = "compaq-peer"
    IPX_IN_IP = "ipx-in-ip"
    CARP = "carp"
    PGM = "pgm"
    L2TP = "l2tp"
    DDX = "ddx"
    IATP = "iatp"
    STP = "stp"
    SRP = "srp"
    UTI = "uti"
    SMP = "smp"
    SM = "sm"
    PTP = "ptp"
    ISIS = "isis"
    CRTP = "crtp"
    CRUDP = "crudp"
    SPS = "sps"
    PIPE = "pipe"
    SCTP = "sctp"
    FC = "fc"
    RSVP_E2E_IGNORE = "rsvp-e2e-ignore"
    UDPLITE = "udplite"
    MPLS_IN_IP = "mpls-in-ip"
    MANET = "manet"
    HIP = "hip"
    SHIM6 = "shim6"
    WESP = "wesp"
    ROHC = "rohc"
    PFSYNC = "pfsync"
    DIVERT = "divert"


class IPProtocol(ListEnum):
    """Represents the IPProtocol."""

    IPv4 = "inet"
    IPv6 = "inet6"
    IPv4_IPv6 = "inet46"


class FirewallRuleStateType(ListEnum):
    """Represents the FirewallRuleStateType."""  # TODO not yet in the ansible parameters

    NONE = "none"
    KEEP_STATE = "keep state"
    SLOPPY_STATE = "sloppy state"
    MODULATE_STATE = "modulate state"
    SYNPROXY_STATE = "synproxy state"


@dataclass
class Source:
    """Represents the source in a firewall rule"""

    any: bool = False
    # Add other source attributes as needed


@dataclass
class Destination:
    """Represents the destination in a firewall rule"""

    any: bool = False
    port: Optional[int] = None
    # Add other destination attributes as needed


@dataclass
class FirewallRule:
    """Used to represent a firewall rule."""

    interface: str
    uuid: Optional[str] = None
    type: FirewallRuleAction = FirewallRuleAction.PASS
    descr: Optional[str] = None
    quick: bool = False
    ipprotocol: IPProtocol = IPProtocol.IPv4
    direction: Optional[FirewallRuleDirection] = None
    protocol: Optional[FirewallRuleProtocol] = None
    source_address: Optional[str] = None
    source_network: Optional[str] = None
    source_port: Optional[str] = None
    source_any: bool = True
    source_not: bool = False
    destination_address: Optional[str] = None
    destination_network: Optional[str] = None
    destination_port: Optional[str] = None
    destination_any: bool = True
    destination_not: bool = False
    disabled: bool = False
    log: bool = False
    category: Optional[str] = None
    statetype: Optional[FirewallRuleStateType] = None

    # TODO ChangeLog

    def __post_init__(self):
        # Manually define the fields and their expected types
        enum_fields = {
            "type": FirewallRuleAction,
            "ipprotocol": IPProtocol,
            "protocol": FirewallRuleProtocol,
            "statetype": FirewallRuleStateType,
            "direction": FirewallRuleDirection,
        }

        for field_name, field_type in enum_fields.items():
            value = getattr(self, field_name)

            # Check if the value is a string and the field_type is a subclass of ListEnum
            if isinstance(value, str) and issubclass(field_type, ListEnum):
                # Convert string to ListEnum
                setattr(self, field_name, field_type.from_string(value))

    def to_etree(self) -> Element:
        """
        Converts the current FirewallRule object to an XML Element.

        This method takes the attributes of the FirewallRule object, represented as a dictionary,
        and constructs an XML Element structure. The method primarily focuses on converting
        attributes related to 'source' and 'destination' into nested XML tags.

        Attributes in the format "source_any", "destination_port", etc., are transformed into
        corresponding XML structures like `<source><any/></source>`. Boolean attributes are
        particularly handled to create empty tags if True (e.g., `<any/>`) or are omitted if False.
        Non-boolean attributes are converted into standard XML tags with values.

        The 'uuid' attribute of the object, if present, is added as an attribute to the XML element.
        Other unnecessary fields are removed during the conversion process.

        Returns:
        Element: An XML Element representing the FirewallRule object.

        Example:
        Given a FirewallRule object with attributes like {"source_any": "1", "source_port": 22},
        the output will be an XML element structured as:
        ```xml
        <rule>
            <source>
                <any/>
                <port>22</port>
            </source>
        </rule>
        ```

        Note: The method assumes the presence of a utility function `dict_to_etree` for
        converting dictionaries to XML elements.
        """

        rule_dict: dict = asdict(self)
        del rule_dict["uuid"]

        for direction in ["source", "destination"]:
            for key in ["address", "network", "port", "any", "not"]:
                current_val: Optional[Any] = rule_dict.get(
                    f"{direction}_{key}"
                )  # source_not = None
                if current_val is not None:
                    if rule_dict.get(direction) is None:
                        rule_dict[direction] = {}

                    # s/d_network
                    if isinstance(current_val, bool):
                        if current_val:
                            rule_dict[direction][key] = None
                    else:
                        rule_dict[direction][key] = current_val
                del rule_dict[f"{direction}_{key}"]
        for rule_key, rule_val in rule_dict.copy().items():
            if rule_val is None or rule_val is False:
                del rule_dict[rule_key]
                continue
            if issubclass(type(rule_val), ListEnum):
                rule_dict[rule_key] = rule_val.value
            elif isinstance(rule_val, bool):
                rule_dict[rule_key] = "1"

        element: Element = xml_utils.dict_to_etree("rule", rule_dict)[0]

        if self.uuid:
            element.attrib["uuid"] = self.uuid

        return element

    @classmethod
    def from_ansible_module_params(cls, params: dict) -> "FirewallRule":
        interface = params.get("interface")
        action = params.get("action")
        description = params.get("description")
        quick = params.get("quick")
        ipprotocol = params.get("ipprotocol")
        direction = params.get("direction")
        protocol = params.get("protocol")
        source_invert = params.get("source_invert")
        source_ip = params.get("source_ip")
        source_any = source_ip is None or source_ip == "any"
        source_port = params.get("source_port")
        destination_invert = params.get("target_invert")
        destination_ip = params.get("target_ip")
        destination_port = params.get("target_port")
        destination_any = destination_ip is None or destination_ip == "any"
        log = params.get("log")
        category = params.get("category")
        disabled = params.get("disabled")

        rule_dict = {
            "interface": interface,
            "type": action,
            "descr": description,
            "quick": quick,
            "ipprotocol": ipprotocol,
            "direction": direction,
            "protocol": protocol,
            "source_not": source_invert,
            "source_address": source_ip if source_ip != "any" else None,
            "source_any": source_any,
            "source_port": source_port,
            "destination_not": destination_invert,
            "destination_address": destination_ip if destination_ip != "any" else None,
            "destination_any": destination_any,
            "destination_port": destination_port,
            "log": log,
            "category": category,
            "disabled": disabled,
        }

        rule_dict = {key: value for key, value in rule_dict.items() if value is not None}

        return cls(**rule_dict)

    @staticmethod
    def from_xml(element: Element) -> "FirewallRule":
        """
        Converts an XML element into a FirewallRule object.

        This static method transforms an XML element, expected to have 'rule' as its root, into a
        FirewallRule object. It handles elements such as 'source', 'destination', and their
        sub-elements like 'address', 'network', 'port', 'any', and 'not'.

        The method processes each direction ('source' or 'destination') and relevant keys.
        'any' and 'not' are converted to booleans, while other values are assigned as is.
        Elements not present are skipped. The 'uuid' attribute is also extracted from the XML.

        Changelog elements ('updated', 'created') are currently ignored.

        Parameters:
        element (Element): XML element with 'rule' as root.

        Returns:
        FirewallRule: Instance populated with data from the XML element.

        Example XML structure:
        ```xml
        <rule uuid="12345">
            <source>
                <any>1</any>
                <port>22</port>
                <address>192.168.1.1/24</address>
                <not>1</not>
            </source>
            <!-- ... other elements ... -->
        </rule>
        """

        rule_dict: dict = xml_utils.etree_to_dict(element)["rule"]

        for direction in ["source", "destination"]:
            if direction not in rule_dict:
                continue
            for key in ["address", "network", "port", "any", "not"]:
                if key in ["any", "not"]:
                    # 'any' and 'not' must be a boolean value, therefore None is treated as False
                    if key not in rule_dict[direction]:
                        rule_dict[f"{direction}_{key}"] = False
                        continue
                    if rule_dict[direction][key] is None or rule_dict[direction][key] == "1":
                        rule_dict[f"{direction}_{key}"] = True
                    else:
                        rule_dict[f"{direction}_{key}"] = False
                else:
                    rule_dict[f"{direction}_{key}"] = rule_dict[direction].get(key, None)

            del rule_dict[direction]

        rule_dict["uuid"] = element.attrib.get("uuid")

        # TODO ignore changelog for now
        rule_dict.pop("updated", None)
        rule_dict.pop("created", None)
        return FirewallRule(**rule_dict)


class FirewallRuleSet(OPNsenseModuleConfig):
    _rules: List[FirewallRule]

    def __init__(self, path: str = "/conf/config.xml"):
        super().__init__(module_name="firewall_rules", path=path)
        self._rules = self._load_rules()

    def _load_rules(self) -> List[FirewallRule]:
        # /opnsense/filter Element containing a list of <rule>
        element_tree_rules: Element = self.get("rules")

        return [FirewallRule.from_xml(element) for element in element_tree_rules]

    @property
    def changed(self) -> bool:
        return self._load_rules() != self._rules

    def add_or_update(self, rule: FirewallRule) -> None:
        existing_rule: Optional[FirewallRule] = next((r for r in self._rules if r == rule), None)
        if existing_rule:
            existing_rule.__dict__.update(rule.__dict__)
        else:
            self._rules.append(rule)

    def delete(self, rule: FirewallRule) -> None:
        self._rules = [r for r in self._rules if r != rule]

    def find(self, **kwargs) -> Optional[FirewallRule]:
        for rule in self._rules:
            match = all(getattr(rule, key, None) == value for key, value in kwargs.items())
            if match:
                return rule
        return None

    def save(self) -> bool:
        if not self.changed:
            return False

        filter_element: Element = self._config_xml_tree.find(self._config_map["rules"])

        self._config_xml_tree.remove(filter_element)
        filter_element.clear()
        filter_element.extend([rule.to_etree() for rule in self._rules])
        self._config_xml_tree.append(filter_element)

        tree: ElementTree = ElementTree(self._config_xml_tree)
        tree.write(self._config_path, encoding="utf-8", xml_declaration=True)
        self._config_xml_tree = self._load_config()

        return True
