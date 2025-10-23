"""Core logic and data structures for the educational Ethernet switch simulator."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Dict, Iterable, Optional

from switch_sim.modules.interfaces import InterfaceManager, Port, VlanInterface
from switch_sim.modules.mac_table import MacTableEntry, MacTableManager
from switch_sim.modules.stp import STPManager
from switch_sim.modules.vlan import Vlan, VlanManager
from switch_sim.services.frame_processing import process_frame as process_frame_service
from switch_sim.utils import format_timestamp, normalize_mac, validate_ipv4_address

DEFAULT_AGING_TIME = timedelta(minutes=5)


@dataclass
class Frame:
    """シミュレーション専用の簡易イーサネットフレームです。"""

    src_mac: str
    dst_mac: str
    payload: str = ""

    def __post_init__(self) -> None:
        self.src_mac = normalize_mac(self.src_mac)
        self.dst_mac = normalize_mac(self.dst_mac)


@dataclass
class UserAccount:
    """ローカルユーザーアカウント情報を保持します。"""

    username: str
    privilege: int
    secret: str


@dataclass
class LineConfig:
    """コンソールおよび VTY ラインの設定を保持します。"""

    name: str
    login_local: bool = False
    transport_input: Optional[str] = None
class EthernetSwitch:
    """教育用途向けの小さなレイヤ 2 イーサネットスイッチモデルです。"""

    def __init__(
        self,
        name: str,
        ports: Iterable[str],
        mac_table_aging: timedelta = DEFAULT_AGING_TIME,
    ) -> None:
        self.name = name
        self._ports: Dict[str, Port] = {port: Port(port) for port in ports}
        if not self._ports:
            raise ValueError("a switch must have at least one port")
        self.mac_table: Dict[str, MacTableEntry] = {}
        self.mac_table_aging = mac_table_aging
        self.event_log: list[str] = []
        self.enable_secret: Optional[str] = None
        self.domain_lookup: bool = True
        self.default_gateway: Optional[str] = None
        self.vlan_interfaces: Dict[int, VlanInterface] = {}
        self.user_accounts: Dict[str, UserAccount] = {}
        self.line_console = LineConfig(name="console 0")
        self.line_vty = LineConfig(name="vty 0 4")
        self.vlans: Dict[int, Vlan] = {1: Vlan(1, "default")}
        self.stp_mode: str = "rapid-pvst"
        self.stp_vlan_priority: Dict[int, int] = {}
        self.port_portfast: Dict[str, bool] = {port: False for port in ports}

        self._mac_manager = MacTableManager(self)
        self._interface_manager = InterfaceManager(self)
        self._vlan_manager = VlanManager(self)
        self._stp_manager = STPManager(self)

    # ------------------------------------------------------------------
    # 設定ヘルパー
    # ------------------------------------------------------------------
    def set_port_admin_state(self, port: str, admin_up: bool) -> None:
        self._interface_manager.set_port_admin_state(port, admin_up)

    def set_port_vlan(self, port: str, vlan: int) -> None:
        self._interface_manager.set_port_vlan(port, vlan)

    def set_port_description(self, port: str, description: str) -> None:
        self._interface_manager.set_port_description(port, description)

    def set_port_mode(self, port: str, mode: str) -> None:
        self._interface_manager.set_port_mode(port, mode)

    def set_port_portfast(self, port: str, enabled: bool) -> None:
        self._interface_manager.set_port_portfast(port, enabled)

    def set_hostname(self, hostname: str) -> None:
        if not hostname:
            raise ValueError("hostname must not be empty")
        self.name = hostname
        self._log(f"Hostname set to {hostname}")

    def set_enable_secret(self, secret: str) -> None:
        if not secret:
            raise ValueError("enable secret must not be empty")
        self.enable_secret = secret
        self._log("Enable secret configured")

    def set_domain_lookup(self, enabled: bool) -> None:
        self.domain_lookup = enabled
        state = "enabled" if enabled else "disabled"
        self._log(f"IP domain lookup {state}")

    def set_default_gateway(self, gateway: str) -> None:
        if not validate_ipv4_address(gateway):
            raise ValueError("invalid IPv4 address")
        self.default_gateway = gateway
        self._log(f"Default gateway set to {gateway}")

    def ensure_vlan_interface(self, vlan: int) -> VlanInterface:
        return self._interface_manager.ensure_vlan_interface(vlan)

    def set_vlan_interface_ip(self, vlan: int, ip: str, mask: str) -> None:
        if not validate_ipv4_address(ip) or not validate_ipv4_address(mask):
            raise ValueError("invalid IPv4 address or mask")
        self._interface_manager.set_vlan_interface_ip(vlan, ip, mask)

    def clear_vlan_interface_ip(self, vlan: int) -> None:
        self._interface_manager.clear_vlan_interface_ip(vlan)

    def set_vlan_interface_admin_state(self, vlan: int, admin_up: bool) -> None:
        self._interface_manager.set_vlan_interface_admin_state(vlan, admin_up)

    def set_vlan_interface_description(self, vlan: int, description: str) -> None:
        self._interface_manager.set_vlan_interface_description(vlan, description)

    def set_user_account(self, username: str, privilege: int, secret: str) -> None:
        if not username:
            raise ValueError("username must not be empty")
        if privilege < 0 or privilege > 15:
            raise ValueError("privilege must be between 0 and 15")
        if not secret:
            raise ValueError("secret must not be empty")
        self.user_accounts[username] = UserAccount(
            username=username, privilege=privilege, secret=secret
        )
        self._log(f"User {username} configured with privilege {privilege}")

    def set_line_login_local(self, line_type: str, enabled: bool) -> None:
        if line_type not in {"console", "vty"}:
            raise ValueError("line_type must be 'console' or 'vty'")
        target = self.line_console if line_type == "console" else self.line_vty
        target.login_local = enabled
        self._log(f"Line {target.name} login local {'enabled' if enabled else 'disabled'}")

    def set_line_transport_input(self, value: str) -> None:
        self.line_vty.transport_input = value
        self._log(f"Line {self.line_vty.name} transport input set to {value}")

    def ensure_vlan(self, vlan: int) -> Vlan:
        return self._vlan_manager.ensure_vlan(vlan)

    def set_vlan_name(self, vlan: int, name: str) -> None:
        self._vlan_manager.set_vlan_name(vlan, name)

    def set_stp_mode(self, mode: str) -> None:
        self._stp_manager.set_mode(mode)

    def set_stp_vlan_priority(self, vlan: int, priority: int) -> None:
        self._stp_manager.set_vlan_priority(vlan, priority)

    def port_portfast_enabled(self, port: str) -> bool:
        return self._interface_manager.port_portfast_enabled(port)

    # ------------------------------------------------------------------
    # 運用ヘルパー
    # ------------------------------------------------------------------
    def process_frame(self, ingress_port: str, frame: Frame) -> Dict[str, Frame]:
        """フレームを処理し、送信されるフレームを返します。"""

        return process_frame_service(self, ingress_port, frame)

    # ------------------------------------------------------------------
    # show コマンド用ヘルパー
    # ------------------------------------------------------------------
    def show_mac_address_table(self) -> str:
        return self._mac_manager.render()

    def show_interfaces_status(self) -> str:
        return self._interface_manager.show_interfaces_status()

    def show_event_log(self, limit: Optional[int] = None) -> str:
        if limit is None:
            events = self.event_log
        else:
            events = self.event_log[-limit:]
        return "\n".join(events) if events else "<no events>"

    def show_interfaces_detail(self, interface: Optional[str] = None) -> str:
        return self._interface_manager.show_interfaces_detail(interface)

    def show_interfaces_description(self) -> str:
        return self._interface_manager.show_interfaces_description()

    def show_ip_interface_brief(self) -> str:
        return self._interface_manager.show_ip_interface_brief()

    def show_vlan_brief(self) -> str:
        return self.show_vlan()

    def show_vlan_id(self, vlan_id: int) -> str:
        return self._vlan_manager.show_vlan_id(vlan_id)

    def show_interfaces_switchport(self) -> str:
        return self._interface_manager.show_interfaces_switchport()

    def show_interfaces_trunk(self) -> str:
        return "Switch has no trunk ports configured."

    def show_running_config(self) -> str:
        non_default_vlans = [
            vlan
            for vlan in self.vlans.values()
            if not (vlan.vlan_id == 1 and vlan.name == "default")
        ]
        total_lines = len(self._ports) + len(self.vlan_interfaces) + len(non_default_vlans)
        lines = [
            "Building configuration...",
            "",
            f"Current configuration : {total_lines} lines (simulated)",
            "!",
            f"hostname {self.name}",
        ]
        if self.enable_secret:
            lines.append(f"enable secret {self.enable_secret}")
        if not self.domain_lookup:
            lines.append("no ip domain-lookup")
        if self.default_gateway:
            lines.append(f"ip default-gateway {self.default_gateway}")
        if self.stp_mode != "rapid-pvst":
            lines.append(f"spanning-tree mode {self.stp_mode}")
        for vlan_id, priority in sorted(self.stp_vlan_priority.items()):
            lines.append(f"spanning-tree vlan {vlan_id} priority {priority}")
        for account in sorted(self.user_accounts.values(), key=lambda a: a.username):
            lines.append(
                f"username {account.username} privilege {account.privilege} secret {account.secret}"
            )
        lines.append("!")
        for vlan in sorted(self.vlans.values(), key=lambda v: v.vlan_id):
            if vlan.vlan_id == 1 and vlan.name == "default":
                continue
            lines.append(f"vlan {vlan.vlan_id}")
            if vlan.name:
                lines.append(f" name {vlan.name}")
            lines.append("!")
        for port in sorted(self._ports.values(), key=lambda p: p.name):
            lines.append(f"interface {port.name}")
            if port.description:
                lines.append(f" description {port.description}")
            lines.append(f" switchport mode {port.mode}")
            lines.append(f" switchport access vlan {port.vlan}")
            if self.port_portfast_enabled(port.name):
                lines.append(" spanning-tree portfast")
            lines.append(" shutdown" if not port.admin_up else " no shutdown")
            lines.append("!")
        for svi in sorted(self.vlan_interfaces.values(), key=lambda i: i.vlan):
            lines.append(f"interface {svi.name}")
            if svi.description:
                lines.append(f" description {svi.description}")
            if svi.ip_address and svi.subnet_mask:
                lines.append(f" ip address {svi.ip_address} {svi.subnet_mask}")
            if svi.admin_up:
                lines.append(" no shutdown")
            else:
                lines.append(" shutdown")
            lines.append("!")
        lines.append("line console 0")
        if self.line_console.login_local:
            lines.append(" login local")
        lines.append("!")
        lines.append("line vty 0 4")
        if self.line_vty.transport_input:
            lines.append(f" transport input {self.line_vty.transport_input}")
        if self.line_vty.login_local:
            lines.append(" login local")
        lines.append("!")
        return "\n".join(lines)

    def show_startup_config(self) -> str:
        return "% Startup configuration not supported in this simulator."

    def show_version(self) -> str:
        lines = [
            f"Simulator IOS Software, {self.name} Software (Educational Edition)",
            "Compiled Tue 01-Jan-24 00:00 by codex",
            "",
            f"System image file is 'flash:switch_simulator.bin'",
            "",
            "System hardware configuration:",
            f"  {len(self._ports)} FastEthernet interfaces",
            "",
            "Configuration register is 0x2102 (simulation)",
        ]
        return "\n".join(lines)

    def show_vlan(self) -> str:
        vlan_members: Dict[int, list[str]] = {}
        for port in self._ports.values():
            vlan_members.setdefault(port.vlan, []).append(port.name)
        lines = ["VLAN Name                             Status    Ports"]
        vlan_ids = sorted(set(self.vlans.keys()) | set(vlan_members.keys()))
        if not vlan_ids:
            lines.append("<no VLANs>")
            return "\n".join(lines)
        for vlan_id in vlan_ids:
            vlan = self.vlans.get(vlan_id) or Vlan(vlan_id=vlan_id)
            ports = ", ".join(sorted(vlan_members.get(vlan_id, [])))
            lines.append(
                f"{vlan_id:<4} {vlan.display_name():<30} active    {ports}"
            )
        return "\n".join(lines)

    def show_spanning_tree(self) -> str:
        lines = [
            f"Spanning tree enabled protocol {self.stp_mode.upper()}",
        ]
        vlan_ids = sorted(self.vlans.keys())
        if not vlan_ids:
            vlan_ids = [1]
        for vlan_id in vlan_ids:
            vlan = self.vlans[vlan_id]
            priority = self.stp_vlan_priority.get(vlan_id, 32768 + vlan_id)
            lines.append(f"\nVLAN{vlan_id:04d}")
            lines.append(f"  Bridge Identifier has priority {priority}")
            portfast_ports = [
                port for port in sorted(self._ports) if self.port_portfast_enabled(port)
            ]
            if portfast_ports:
                lines.append("  Portfast enabled on:")
                for port in portfast_ports:
                    lines.append(f"    {port}")
            else:
                lines.append("  Portfast enabled on: <none>")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # メンテナンスヘルパー
    # ------------------------------------------------------------------
    def clear_mac_table(self) -> None:
        self._mac_manager.clear()

    def _require_port(self, port: str) -> Port:
        return self._interface_manager.require_port(port)

    def _get_interface_by_name(self, name: str):
        return self._interface_manager.get_interface_by_name(name)

    def _log(self, message: str) -> None:
        timestamp = format_timestamp()
        self.event_log.append(f"[{timestamp}] {message}")


__all__ = [
    "DEFAULT_AGING_TIME",
    "normalize_mac",
    "validate_ipv4_address",
    "Frame",
    "MacTableEntry",
    "Port",
    "VlanInterface",
    "UserAccount",
    "LineConfig",
    "Vlan",
    "EthernetSwitch",
]
