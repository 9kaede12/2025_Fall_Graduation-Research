"""Interface configuration helpers for the educational Ethernet switch simulator."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, TYPE_CHECKING, Union

__all__ = ["Port", "VlanInterface", "InterfaceManager"]

if TYPE_CHECKING:  # pragma: no cover - 型チェック専用
    from switch_sim.switch_core import EthernetSwitch


@dataclass
class Port:
    """設定および監視に用いるスイッチポートの状態を表します。"""

    name: str
    vlan: int = 1
    admin_up: bool = True
    description: str = ""
    mode: str = "access"

    def status(self) -> str:
        return "connected" if self.admin_up else "administratively down"


@dataclass
class VlanInterface:
    """VLAN インターフェース (SVI) の状態を管理します。"""

    vlan: int
    name: str
    ip_address: Optional[str] = None
    subnet_mask: Optional[str] = None
    admin_up: bool = True
    description: str = ""

    def status(self) -> str:
        return "up" if self.admin_up else "administratively down"


class InterfaceManager:
    """スイッチポートおよび VLAN インターフェースの共通操作を提供します。"""

    def __init__(self, switch: "EthernetSwitch") -> None:
        self._switch = switch

    def require_port(self, port: str) -> Port:
        try:
            return self._switch._ports[port]
        except KeyError as exc:  # pragma: no cover - テストで検証済み
            raise ValueError(f"unknown port: {port}") from exc

    def get_interface_by_name(self, name: str) -> Union[Port, VlanInterface]:
        if name in self._switch._ports:
            return self._switch._ports[name]
        lowered = name.lower()
        for port_name, port in self._switch._ports.items():
            if port_name.lower() == lowered:
                return port
        if lowered.startswith("vlan"):
            try:
                vlan_id = int(lowered[4:])
            except ValueError as exc:
                raise ValueError(f"unknown interface: {name}") from exc
            interface = self._switch.vlan_interfaces.get(vlan_id)
            if interface is not None:
                return interface
        for interface in self._switch.vlan_interfaces.values():
            if interface.name.lower() == lowered:
                return interface
        raise ValueError(f"unknown interface: {name}")

    def set_port_admin_state(self, port: str, admin_up: bool) -> None:
        port_obj = self.require_port(port)
        port_obj.admin_up = admin_up
        self._switch._log(f"Port {port} administratively {'up' if admin_up else 'down'}")

    def set_port_vlan(self, port: str, vlan: int) -> None:
        self._switch.ensure_vlan(vlan)
        port_obj = self.require_port(port)
        port_obj.vlan = vlan
        self._switch._log(f"Port {port} assigned to VLAN {vlan}")

    def set_port_description(self, port: str, description: str) -> None:
        port_obj = self.require_port(port)
        port_obj.description = description
        self._switch._log(f"Description set on {port}: {description}")

    def set_port_mode(self, port: str, mode: str) -> None:
        normalized = mode.lower()
        if normalized != "access":
            raise ValueError("only access mode is supported in this simulator")
        port_obj = self.require_port(port)
        port_obj.mode = normalized
        self._switch._log(f"Port {port} mode set to {normalized}")

    def set_port_portfast(self, port: str, enabled: bool) -> None:
        port_obj = self.require_port(port)
        if port_obj.mode != "access" and enabled:
            raise ValueError("portfast is only valid on access ports")
        self._switch.port_portfast[port] = enabled
        state = "enabled" if enabled else "disabled"
        self._switch._log(f"Port {port} spanning-tree portfast {state}")

    def port_portfast_enabled(self, port: str) -> bool:
        return self._switch.port_portfast.get(port, False)

    def ensure_vlan_interface(self, vlan: int) -> VlanInterface:
        self._switch.ensure_vlan(vlan)
        interface = self._switch.vlan_interfaces.get(vlan)
        if interface is None:
            name = f"Vlan{vlan}"
            interface = VlanInterface(vlan=vlan, name=name)
            self._switch.vlan_interfaces[vlan] = interface
            self._switch._log(f"Created interface {name}")
        return interface

    def set_vlan_interface_ip(self, vlan: int, ip: str, mask: str) -> None:
        interface = self.ensure_vlan_interface(vlan)
        interface.ip_address = ip
        interface.subnet_mask = mask
        self._switch._log(f"Interface {interface.name} IP set to {ip} {mask}")

    def clear_vlan_interface_ip(self, vlan: int) -> None:
        interface = self.ensure_vlan_interface(vlan)
        interface.ip_address = None
        interface.subnet_mask = None
        self._switch._log(f"Interface {interface.name} IP address cleared")

    def set_vlan_interface_admin_state(self, vlan: int, admin_up: bool) -> None:
        interface = self.ensure_vlan_interface(vlan)
        interface.admin_up = admin_up
        self._switch._log(
            f"Interface {interface.name} administratively {'up' if admin_up else 'down'}"
        )

    def set_vlan_interface_description(self, vlan: int, description: str) -> None:
        interface = self.ensure_vlan_interface(vlan)
        interface.description = description
        self._switch._log(f"Description set on {interface.name}: {description}")

    def show_interfaces_status(self) -> str:
        lines = ["Port            Status                  VLAN  Description"]
        interfaces: Iterable[Union[Port, VlanInterface]] = list(self._switch._ports.values()) + list(
            self._switch.vlan_interfaces.values()
        )
        for port in sorted(interfaces, key=lambda iface: iface.name):
            vlan = getattr(port, "vlan", 1)
            lines.append(f"{port.name:<15}{port.status():<24}{vlan:<5} {port.description}")
        return "\n".join(lines)

    def show_interfaces_detail(self, interface: Optional[str] = None) -> str:
        if interface is not None:
            ports = [self.get_interface_by_name(interface)]
        else:
            ports = list(self._switch._ports.values()) + list(self._switch.vlan_interfaces.values())
            ports.sort(key=lambda iface: iface.name)
        lines: list[str] = []
        for iface in ports:
            if isinstance(iface, VlanInterface):
                status_line = (
                    f"{iface.name} is up" if iface.admin_up else f"{iface.name} is administratively down"
                )
            else:
                status_line = (
                    f"{iface.name} is connected" if iface.admin_up else f"{iface.name} is administratively down"
                )
            lines.append(status_line)
            lines.append(f"  VLAN {iface.vlan}")
            if isinstance(iface, VlanInterface):
                if iface.ip_address and iface.subnet_mask:
                    lines.append(
                        f"  Internet address is {iface.ip_address}/{iface.subnet_mask}"
                    )
                else:
                    lines.append("  Internet address is unassigned")
            description = iface.description or "<no description>"
            lines.append(f"  Description: {description}")
            lines.append("")
        if not lines:
            return "<no interfaces>"
        return "\n".join(lines).rstrip()

    def show_interfaces_description(self) -> str:
        lines = ["Interface        Status          Description"]
        interfaces = list(self._switch._ports.values()) + list(self._switch.vlan_interfaces.values())
        interfaces.sort(key=lambda iface: iface.name)
        for port in interfaces:
            status = port.status()
            description = port.description or ""
            lines.append(f"{port.name:<16}{status:<16}{description}")
        return "\n".join(lines)

    def show_interfaces_switchport(self) -> str:
        lines: list[str] = []
        for port in self._switch._ports.values():
            lines.append(f"Name: {port.name}")
            lines.append("Switchport: Enabled")
            lines.append(f"Administrative Mode: static {port.mode}")
            lines.append(f"Operational Mode: static {port.mode}")
            lines.append(f"Access Mode VLAN: {port.vlan}")
            lines.append("Trunking Native Mode VLAN: 1")
            lines.append("Voice VLAN: none")
            lines.append(
                f"Portfast: {'Enabled' if self.port_portfast_enabled(port.name) else 'Disabled'}"
            )
            lines.append("")
        if not lines:
            return "<no interfaces>"
        return "\n".join(lines).rstrip()

    def show_ip_interface_brief(self) -> str:
        lines = [
            "Interface              IP-Address      OK? Method Status                Protocol"
        ]
        interfaces = list(self._switch._ports.values()) + list(self._switch.vlan_interfaces.values())
        interfaces.sort(key=lambda iface: iface.name)
        for port in interfaces:
            status = "up" if port.admin_up else "administratively down"
            protocol = "up" if port.admin_up else "down"
            ip_address = "unassigned"
            if isinstance(port, VlanInterface) and port.ip_address:
                ip_address = port.ip_address
            lines.append(
                f"{port.name:<22}{ip_address:<15}YES manual {status:<20}{protocol}"
            )
        return "\n".join(lines)
