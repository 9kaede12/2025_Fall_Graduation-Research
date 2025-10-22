"""教育用 Cisco ルーターシミュレータのエントリポイント。

基本的なインターフェース管理および設定コマンドを模倣し、学習用途で
コマンド操作に慣れることを目的としています。実データプレーン処理は行いません。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
from ipaddress import IPv4Address, IPv4Network, IPv4Interface

from .static_route import StaticRoute
from .ospf import OspfNetwork
from .bgp import BgpNeighbor, BgpNetwork


@dataclass(frozen=True)
class NatPool:
    name: str
    start: IPv4Address
    end: IPv4Address
    netmask: IPv4Address


@dataclass(frozen=True)
class NatMapping:
    access_list: str
    pool: str
    overload: bool
from typing import Dict, Iterable, Optional


def _validate_ipv4(value: str) -> bool:
    """IPv4 アドレス形式を検証します。"""

    try:
        IPv4Address(value)
    except ValueError:
        return False
    return True


def _generate_mac(index: int) -> str:
    """インターフェース番号から安定した疑似 MAC アドレスを生成します。"""

    base = 0x02_00_00_00_00_00
    value = base + index
    octets = [(value >> shift) & 0xFF for shift in range(40, -1, -8)]
    return ":".join(f"{octet:02x}" for octet in octets)


@dataclass
class RouterInterface:
    """ルーターのインターフェース状態を表現します。"""

    name: str
    mac_address: str
    ip_address: Optional[str] = None
    subnet_mask: Optional[str] = None
    admin_up: bool = False
    description: str = ""
    nat_role: str = "none"

    def oper_status(self) -> str:
        """運用状態を返します（簡易化のため admin と同一とする）。"""

        return "up" if self.admin_up else "administratively down"


class CiscoRouter:
    """教育用の簡易 Cisco ルーターモデル。"""

    def __init__(self, name: str, interfaces: Iterable[str]) -> None:
        self.name = name
        self._interfaces: Dict[str, RouterInterface] = {}
        for index, iface in enumerate(interfaces):
            self._interfaces[iface] = RouterInterface(
                name=iface,
                mac_address=_generate_mac(index),
            )
        if not self._interfaces:
            raise ValueError("router requires at least one interface")
        self.enable_secret: Optional[str] = None
        self.password_encryption: bool = False
        self.domain_lookup_enabled: bool = True
        self.banner_motd: Optional[str] = None
        self.clock_timezone: Optional[tuple[str, int]] = None
        self.service_timestamps_enabled: bool = False
        self.event_log: list[str] = []
        self.startup_config: Optional[str] = None
        self.vlans: set[int] = set()
        self.static_routes: set[StaticRoute] = set()
        self.rip_enabled: bool = False
        self.rip_version: int = 2
        self.rip_auto_summary: bool = True
        self.rip_networks: set[IPv4Network] = set()
        self.rip_redistribute_static: bool = False
        self.ospf_enabled: bool = False
        self.ospf_process_id: Optional[int] = None
        self.ospf_router_id: Optional[IPv4Address] = None
        self.ospf_networks: set[OspfNetwork] = set()
        self.ospf_redistribute_static: bool = False
        self.bgp_enabled: bool = False
        self.bgp_asn: Optional[int] = None
        self.bgp_neighbors: Dict[IPv4Address, BgpNeighbor] = {}
        self.bgp_networks: set[BgpNetwork] = set()
        self.bgp_redistribute_static: bool = False
        self.arp_table: Dict[str, dict] = {}
        self.name_servers: list[IPv4Address] = []
        self.nat_pools: Dict[str, NatPool] = {}
        self.nat_mappings: list[NatMapping] = []

    # ------------------------------------------------------------------
    # 設定ヘルパー
    # ------------------------------------------------------------------
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

    def set_service_timestamps(self, enabled: bool) -> None:
        self.service_timestamps_enabled = enabled
        state = "enabled" if enabled else "disabled"
        self._log(f"Service timestamps {state}")

    def _require_interface(self, interface: str) -> RouterInterface:
        try:
            return self._interfaces[interface]
        except KeyError as exc:
            raise ValueError(f"unknown interface: {interface}") from exc

    def set_interface_ip(self, interface: str, ip: str, mask: str) -> None:
        if not (_validate_ipv4(ip) and _validate_ipv4(mask)):
            raise ValueError("invalid IPv4 address or mask")
        iface = self._require_interface(interface)
        old_ip = iface.ip_address
        iface.ip_address = ip
        iface.subnet_mask = mask
        self._log(f"{interface} IP configured to {ip} {mask}")
        if old_ip and old_ip != ip:
            self._remove_arp_entry(old_ip, interface)
        self._add_arp_entry(ip, iface.mac_address, interface, static=True)

    def clear_interface_ip(self, interface: str) -> None:
        iface = self._require_interface(interface)
        old_ip = iface.ip_address
        iface.ip_address = None
        iface.subnet_mask = None
        self._log(f"{interface} IP configuration removed")
        if old_ip:
            self._remove_arp_entry(old_ip, interface)

    def set_interface_admin_state(self, interface: str, admin_up: bool) -> None:
        iface = self._require_interface(interface)
        iface.admin_up = admin_up
        self._log(
            f"{interface} administratively {'up' if admin_up else 'down'}"
        )

    def set_interface_description(self, interface: str, description: str) -> None:
        iface = self._require_interface(interface)
        iface.description = description
        self._log(f"{interface} description set to '{description}'")

    def set_interface_nat_role(self, interface: str, role: str) -> None:
        iface = self._require_interface(interface)
        if role not in {"inside", "outside"}:
            raise ValueError("role must be 'inside' or 'outside'")
        iface.nat_role = role
        self._log(f"{interface} configured as NAT {role}")

    def clear_interface_nat_role(self, interface: str, role: Optional[str] = None) -> None:
        iface = self._require_interface(interface)
        if role and iface.nat_role != role:
            return
        if iface.nat_role != "none":
            iface.nat_role = "none"
            self._log(f"{interface} NAT role cleared")

    # ------------------------------------------------------------------
    # show コマンド
    # ------------------------------------------------------------------
    def show_interfaces(self) -> str:
        lines: list[str] = []
        for iface in self._interfaces.values():
            lines.append(
                f"{iface.name} is {iface.oper_status()}, line protocol is {iface.oper_status()}"
            )
            lines.append(f"  Hardware is GenericEthernet, address is {iface.mac_address}")
            if iface.ip_address and iface.subnet_mask:
                lines.append(f"  Internet address is {iface.ip_address} {iface.subnet_mask}")
            else:
                lines.append("  Internet address is unassigned")
            desc = iface.description or "<no description>"
            lines.append(f"  Description: {desc}")
            lines.append("")
        return "\n".join(lines).rstrip()

    def show_ip_interface_brief(self) -> str:
        header = "Interface              IP-Address      OK? Method Status                Protocol"
        rows = [header]
        for iface in self._interfaces.values():
            ip = iface.ip_address or "unassigned"
            status = "up" if iface.admin_up else "administratively down"
            protocol = "up" if iface.admin_up else "down"
            rows.append(
                f"{iface.name:<22}{ip:<15}YES manual {status:<20}{protocol}"
            )
        return "\n".join(rows)

    def show_running_config(self) -> str:
        lines = [
            "Building configuration...",
            "",
            "Current configuration : 1 lines (simulated)",
            "!",
            f"hostname {self.name}",
        ]
        if self.enable_secret:
            if self.password_encryption:
                hashed = hashlib.sha256(self.enable_secret.encode()).hexdigest()[:16]
                lines.append(f"enable secret 5 {hashed}")
            else:
                lines.append(f"enable secret {self.enable_secret}")
        if self.password_encryption:
            lines.append("service password-encryption")
        if not self.domain_lookup_enabled:
            lines.append("no ip domain-lookup")
        if self.service_timestamps_enabled:
            lines.append("service timestamps log datetime")
        if self.clock_timezone:
            name, offset = self.clock_timezone
            lines.append(f"clock timezone {name} {offset}")
        if self.banner_motd is not None:
            lines.append(f"banner motd #{self.banner_motd}#")
        for vlan in sorted(self.vlans):
            lines.append(f"vlan {vlan}")
        lines.append("!")
        for route in sorted(self.static_routes, key=lambda r: (int(r.network.network_address), r.network.prefixlen)):
            lines.append(f"ip route {route.network.network_address.exploded} {route.network.netmask.exploded} {route.next_hop.exploded}")
        if self.static_routes:
            lines.append("!")
        for pool in sorted(self.nat_pools.values(), key=lambda p: p.name.lower()):
            lines.append(
                f"ip nat pool {pool.name} {pool.start.exploded} {pool.end.exploded} netmask {pool.netmask.exploded}"
            )
        if self.nat_pools:
            lines.append("!")
        for mapping in sorted(self.nat_mappings, key=lambda m: (m.access_list, m.pool)):
            line = f"ip nat inside source list {mapping.access_list} pool {mapping.pool}"
            if mapping.overload:
                line += " overload"
            lines.append(line)
        if self.nat_mappings:
            lines.append("!")
        if self.name_servers:
            lines.append("ip name-server " + " ".join(ns.exploded for ns in self.name_servers))
            lines.append("!")
        if self.rip_enabled:
            lines.append("router rip")
            lines.append(f" version {self.rip_version}")
            if self.rip_auto_summary:
                lines.append(" auto-summary")
            else:
                lines.append(" no auto-summary")
            if self.rip_redistribute_static:
                lines.append(" redistribute static")
            for network in sorted(self.rip_networks, key=lambda n: (int(n.network_address), n.prefixlen)):
                lines.append(f" network {network.network_address.exploded}")
            lines.append("!")
        if self.ospf_enabled and self.ospf_process_id is not None:
            lines.append(f"router ospf {self.ospf_process_id}")
            if self.ospf_router_id:
                lines.append(f" router-id {self.ospf_router_id.exploded}")
            if self.ospf_redistribute_static:
                lines.append(" redistribute static")
            for entry in sorted(self.ospf_networks, key=lambda e: (int(e.network.network_address), e.area)):
                lines.append(
                    f" network {entry.network.network_address.exploded} {entry.wildcard.exploded} area {entry.area}"
                )
            lines.append("!")
        if self.bgp_enabled and self.bgp_asn is not None:
            lines.append(f"router bgp {self.bgp_asn}")
            for neighbor in sorted(self.bgp_neighbors.values(), key=lambda n: int(n.address)):
                lines.append(f" neighbor {neighbor.address.exploded} remote-as {neighbor.remote_as}")
            for network in sorted(self.bgp_networks, key=lambda n: int(n.prefix.network_address)):
                lines.append(
                    f" network {network.prefix.network_address.exploded} mask {network.prefix.netmask.exploded}"
                )
            if self.bgp_redistribute_static:
                lines.append(" redistribute static")
            lines.append("!")
        for iface in self._interfaces.values():
            lines.append(f"interface {iface.name}")
            if iface.description:
                lines.append(f" description {iface.description}")
            if iface.ip_address and iface.subnet_mask:
                lines.append(f" ip address {iface.ip_address} {iface.subnet_mask}")
            else:
                lines.append(" no ip address")
            if iface.nat_role == "inside":
                lines.append(" ip nat inside")
            elif iface.nat_role == "outside":
                lines.append(" ip nat outside")
            if iface.admin_up:
                lines.append(" no shutdown")
            else:
                lines.append(" shutdown")
            lines.append("!")
        return "\n".join(lines)

    def show_startup_config(self) -> str:
        if self.startup_config is None:
            return "% No startup configuration present."
        return self.startup_config

    def show_version(self) -> str:
        return (
            f"Cisco IOS Software, {self.name} Software (Educational Edition)\n"
            "Compiled Thu 01-Jan-24 00:00 by codex\n\n"
            "ROM: Bootstrap program is RouterSim\n"
            "System restarted at 00:00:00 UTC Sun Jan 1 2024\n"
            "System image file is 'flash:router_sim.bin'\n"
        )

    def show_processes(self) -> str:
        return (
            "PID  Runtime(ms)  Invoked   uSecs   5Sec   1Min   5Min  TTY Process\n"
            "1    100          10        10000   0%     0%     0%    *   Init\n"
            "2    50           5         10000   0%     0%     0%    *   CLI\n"
        )

    def show_users(self) -> str:
        return (
            "    Line       User       Host(s)              Idle       Location\n"
            "   *    0 con 0            idle                 00:00:00\n"
        )

    def show_ip_route(self) -> str:
        lines = [
            "Codes: C - connected, S - static, R - RIP",
            "",
            "Gateway of last resort is not set",
            "",
        ]

        connected_networks: list[tuple[IPv4Network, str]] = []
        for iface in self._interfaces.values():
            if iface.ip_address and iface.subnet_mask and iface.admin_up:
                interface = IPv4Interface(f"{iface.ip_address}/{iface.subnet_mask}")
                connected_networks.append((interface.network, iface.name))

        static_routes = sorted(self.static_routes, key=lambda r: (int(r.network.network_address), r.network.prefixlen))
        connected_networks.sort(key=lambda item: (int(item[0].network_address), item[0].prefixlen))

        for network, iface_name in connected_networks:
            lines.append(
                f"C        {network.with_prefixlen:<18} is directly connected, {iface_name}"
            )

        for route in static_routes:
            lines.append(
                f"S        {route.network.with_prefixlen:<18} [1/0] via {route.next_hop}"
            )

        if self.rip_enabled:
            for network in sorted(self.rip_networks, key=lambda n: (int(n.network_address), n.prefixlen)):
                if any(network == connected for connected, _ in connected_networks):
                    continue
                if any(network == route.network for route in static_routes):
                    continue
                lines.append(
                    f"R        {network.with_prefixlen:<18} [120/1] via 0.0.0.0"
                )
            if self.rip_redistribute_static:
                for route in static_routes:
                    lines.append(
                        f"R        {route.network.with_prefixlen:<18} [120/1] via {route.next_hop}"
                    )

        if self.ospf_enabled:
            for entry in sorted(self.ospf_networks, key=lambda e: (int(e.network.network_address), e.area)):
                if any(entry.network == connected for connected, _ in connected_networks):
                    continue
                if any(entry.network == route.network for route in static_routes):
                    continue
                lines.append(
                    f"O        {entry.network.with_prefixlen:<18} [110/20] via 0.0.0.0"
                )
            if self.ospf_redistribute_static:
                for route in static_routes:
                    lines.append(
                        f"O        {route.network.with_prefixlen:<18} [110/20] via {route.next_hop}"
                    )

        if self.bgp_enabled:
            for network in sorted(self.bgp_networks, key=lambda n: int(n.prefix.network_address)):
                lines.append(
                    f"B        {network.prefix.with_prefixlen:<18} [20/0] via 0.0.0.0"
                )
            if self.bgp_redistribute_static:
                for route in static_routes:
                    lines.append(
                        f"B        {route.network.with_prefixlen:<18} [20/0] via {route.next_hop}"
                    )

        if len(lines) == 4:
            lines.append("<no routes>")
        return "\n".join(lines)

    def show_ip_protocols(self) -> str:
        sections: list[str] = []
        if self.rip_enabled:
            rip_lines = [
                "Routing Protocol is \"rip\"",
                "  Sending updates every 30 seconds, Next due in 30 seconds",
                "  Routing for Networks:",
            ]
            if self.rip_networks:
                for network in sorted(self.rip_networks, key=lambda n: (int(n.network_address), n.prefixlen)):
                    rip_lines.append(f"    {network.network_address.exploded}")
            else:
                rip_lines.append("    <none>")
            rip_lines.append(f"  Using version {self.rip_version}")
            rip_lines.append(f"  Auto-summary is {'enabled' if self.rip_auto_summary else 'disabled'}")
            if self.rip_redistribute_static and self.static_routes:
                rip_lines.append("  Redistributing: static")
            sections.append("\n".join(rip_lines))

        if self.ospf_enabled and self.ospf_process_id is not None:
            ospf_lines = [
                f"Routing Protocol is \"ospf {self.ospf_process_id}\"",
                f"  Router ID { (self.ospf_router_id or self._auto_router_id()).exploded }",
                "  Routing for Networks:",
            ]
            if self.ospf_networks:
                for entry in sorted(self.ospf_networks, key=lambda e: (int(e.network.network_address), e.area)):
                    ospf_lines.append(
                        f"    {entry.network.network_address.exploded} {entry.wildcard.exploded} area {entry.area}"
                    )
            else:
                ospf_lines.append("    <none>")
            if self.ospf_redistribute_static and self.static_routes:
                ospf_lines.append("  Redistributing: static")
            sections.append("\n".join(ospf_lines))

        if self.bgp_enabled and self.bgp_asn is not None:
            bgp_lines = [
                f"Routing Protocol is \"bgp {self.bgp_asn}\"",
                "  BGP table version 1",
                "  Neighboring ASes:",
            ]
            if self.bgp_neighbors:
                for neighbor in sorted(self.bgp_neighbors.values(), key=lambda n: int(n.address)):
                    bgp_lines.append(
                        f"    {neighbor.address.exploded} (AS {neighbor.remote_as})"
                    )
            else:
                bgp_lines.append("    <none>")
            if self.bgp_networks:
                bgp_lines.append("  Advertised networks:")
                for network in sorted(self.bgp_networks, key=lambda n: int(n.prefix.network_address)):
                    bgp_lines.append(f"    {network.prefix.with_prefixlen}")
            if self.bgp_redistribute_static and self.static_routes:
                bgp_lines.append("  Redistributing: static")
            sections.append("\n".join(bgp_lines))

        if not sections:
            return "Routing Protocol is not running"
        return "\n\n".join(sections)
        
    def show_ip_bgp(self) -> str:
        if not self.bgp_enabled:
            return "% BGP not running"
        lines = [
            f"BGP table is for AS {self.bgp_asn}",
            "",
            "     Network          Next Hop        Metric LocPrf Weight Path",
        ]
        if not self.bgp_networks:
            lines.append("<no BGP network entries>")
        else:
            for network in sorted(self.bgp_networks, key=lambda n: int(n.prefix.network_address)):
                lines.append(f"*   {network.prefix.with_prefixlen:<18} 0.0.0.0       0      100    0    ?")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # ICMP ヘルパー
    # ------------------------------------------------------------------
    def _known_networks(self) -> list[IPv4Network]:
        networks: list[IPv4Network] = []
        for iface in self._interfaces.values():
            if iface.ip_address and iface.subnet_mask:
                interface = IPv4Interface(f"{iface.ip_address}/{iface.subnet_mask}")
                networks.append(interface.network)
        networks.extend(route.network for route in self.static_routes)
        networks.extend(self.rip_networks)
        networks.extend(entry.network for entry in self.ospf_networks)
        networks.extend(network.prefix for network in self.bgp_networks)
        return networks

    def _is_ip_reachable(self, target: str) -> bool:
        if not _validate_ipv4(target):
            return False
        address = IPv4Address(target)
        for iface in self._interfaces.values():
            if iface.ip_address and IPv4Address(iface.ip_address) == address:
                return True
        for network in self._known_networks():
            if address in network:
                return True
        return False

    def _resolve_hostname(self, hostname: str) -> Optional[str]:
        if not self.name_servers:
            return None
        digest = hashlib.md5(hostname.encode()).hexdigest()
        last_octet = int(digest[:2], 16) % 254 + 1
        resolved = IPv4Address(f"203.0.113.{last_octet}")
        self._log(f"DNS resolved {hostname} to {resolved.exploded}")
        return resolved.exploded

    def ping(self, target: str) -> str:
        translation_msg: Optional[str] = None
        destination = target
        if not _validate_ipv4(target):
            resolved = self._resolve_hostname(target)
            if resolved is None:
                return f'Translating "{target}"...\n% Unknown host'
            translation_msg = (
                f'Translating "{target}"...domain server '
                f'({", ".join(ns.exploded for ns in self.name_servers)})'
            )
            destination = resolved
        lines = ["Type escape sequence to abort."]
        if translation_msg:
            lines.insert(0, translation_msg)
        lines.append(
            f"Sending 5, 100-byte ICMP Echos to {destination}, timeout is 2 seconds:"
        )
        success = self._is_ip_reachable(destination)
        pattern = "!!!!!" if success else "....."
        lines.append(pattern)
        lines.append("")
        if success:
            lines.append("Success rate is 100 percent (5/5), round-trip min/avg/max = 1/1/1 ms")
        else:
            lines.append("Success rate is 0 percent (0/5)")
        return "\n".join(lines)

    def traceroute(self, target: str) -> str:
        translation_msg: Optional[str] = None
        destination = target
        if not _validate_ipv4(target):
            resolved = self._resolve_hostname(target)
            if resolved is None:
                return f'Translating "{target}"...\n% Unknown host'
            translation_msg = (
                f'Translating "{target}"...domain server '
                f'({", ".join(ns.exploded for ns in self.name_servers)})'
            )
            destination = resolved
        lines = []
        if translation_msg:
            lines.append(translation_msg)
        lines.append(f"Tracing the route to {destination}")
        success = self._is_ip_reachable(destination)
        if success:
            lines.append("  1  1.1.1.1  1 msec 1 msec 1 msec")
            lines.append(f"  2  {destination}  2 msec 2 msec 2 msec")
        else:
            lines.append("  1  *  *  *")
        return "\n".join(lines)

    def save_startup_config(self) -> None:
        self.startup_config = self.show_running_config()
        self._log("Configuration saved to startup-config (simulated)")

    def reload(self) -> str:
        self._log("Reload requested (simulated)")
        return (
            "System configuration has been modified. Reloading the router...\n"
            "Reload complete (simulation only; state preserved)."
        )

    def set_password_encryption(self, enabled: bool) -> None:
        self.password_encryption = enabled
        state = "enabled" if enabled else "disabled"
        self._log(f"Service password encryption {state}")

    def set_domain_lookup(self, enabled: bool) -> None:
        self.domain_lookup_enabled = enabled
        state = "enabled" if enabled else "disabled"
        self._log(f"IP domain lookup {state}")

    def set_banner_motd(self, message: Optional[str]) -> None:
        self.banner_motd = message
        if message is None:
            self._log("Banner MOTD cleared")
        else:
            self._log("Banner MOTD configured")

    def set_clock_timezone(self, name: str, offset: int) -> None:
        self.clock_timezone = (name, offset)
        self._log(f"Clock timezone set to {name} {offset}")

    def set_name_servers(self, servers: list[str]) -> None:
        if not servers:
            raise ValueError("at least one name-server address is required")
        validated: list[IPv4Address] = []
        for server in servers:
            if not _validate_ipv4(server):
                raise ValueError("invalid name-server address")
            validated.append(IPv4Address(server))
        self.name_servers = validated
        self._log("Name server(s) configured: " + ", ".join(str(ns) for ns in self.name_servers))

    def remove_name_servers(self, servers: Optional[list[str]] = None) -> None:
        if not servers:
            self.name_servers.clear()
            self._log("All name servers removed")
            return
        to_remove = []
        for server in servers:
            if not _validate_ipv4(server):
                raise ValueError("invalid name-server address")
            to_remove.append(IPv4Address(server))
        before = set(self.name_servers)
        self.name_servers = [ns for ns in self.name_servers if ns not in to_remove]
        removed = before - set(self.name_servers)
        if removed:
            self._log("Removed name servers: " + ", ".join(str(ns) for ns in removed))

    def create_vlan(self, vlan: int) -> None:
        if vlan <= 0 or vlan > 4094:
            raise ValueError("VLAN ID must be between 1 and 4094")
        if vlan in self.vlans:
            self._log(f"VLAN {vlan} already exists")
            return
        self.vlans.add(vlan)
        self._log(f"VLAN {vlan} created")

    def delete_vlan(self, vlan: int) -> None:
        if vlan not in self.vlans:
            raise ValueError(f"VLAN {vlan} does not exist")
        self.vlans.remove(vlan)
        self._log(f"VLAN {vlan} deleted")

    def add_static_route(self, destination: str, mask: str, next_hop: str) -> None:
        if not (_validate_ipv4(destination) and _validate_ipv4(mask) and _validate_ipv4(next_hop)):
            raise ValueError("invalid IPv4 address")
        network = IPv4Network(f"{destination}/{mask}", strict=False)
        route = StaticRoute(network=network, next_hop=IPv4Address(next_hop))
        if route in self.static_routes:
            self._log(f"Static route {route.description()} already configured")
        else:
            self.static_routes.add(route)
            self._log(f"Static route {route.description()} added")

    def remove_static_route(self, destination: str, mask: str, next_hop: str) -> None:
        if not (_validate_ipv4(destination) and _validate_ipv4(mask) and _validate_ipv4(next_hop)):
            raise ValueError("invalid IPv4 address")
        network = IPv4Network(f"{destination}/{mask}", strict=False)
        route = StaticRoute(network=network, next_hop=IPv4Address(next_hop))
        if route not in self.static_routes:
            raise ValueError("static route not found")
        self.static_routes.remove(route)
        self._log(f"Static route {route.description()} removed")

    def enable_rip(self) -> None:
        if not self.rip_enabled:
            self._log("RIP enabled")
        self.rip_enabled = True

    def disable_rip(self) -> None:
        if self.rip_enabled:
            self._log("RIP disabled")
        self.rip_enabled = False
        self.rip_networks.clear()
        self.rip_version = 2
        self.rip_auto_summary = True
        self.rip_redistribute_static = False

    def set_rip_version(self, version: int) -> None:
        if version not in {1, 2}:
            raise ValueError("RIP version must be 1 or 2")
        self.rip_version = version
        self._log(f"RIP version set to {version}")

    def set_rip_auto_summary(self, enabled: bool) -> None:
        self.rip_auto_summary = enabled
        state = "enabled" if enabled else "disabled"
        self._log(f"RIP auto-summary {state}")

    def set_rip_redistribute_static(self, enabled: bool) -> None:
        self.rip_redistribute_static = enabled
        state = "enabled" if enabled else "disabled"
        self._log(f"RIP redistribute static {state}")

    def add_rip_network(self, value: str) -> None:
        network = self._parse_rip_network(value)
        if network in self.rip_networks:
            self._log(f"RIP network {network.network_address.exploded} already exists")
        else:
            self.rip_networks.add(network)
            self._log(f"RIP network {network.network_address.exploded} added")

    def remove_rip_network(self, value: str) -> None:
        network = self._parse_rip_network(value)
        if network not in self.rip_networks:
            raise ValueError("network not found in RIP configuration")
        self.rip_networks.remove(network)
        self._log(f"RIP network {network.network_address.exploded} removed")

    @staticmethod
    def _parse_rip_network(value: str) -> IPv4Network:
        if "/" in value:
            return IPv4Network(value, strict=False)
        if not _validate_ipv4(value):
            raise ValueError("invalid IPv4 network address")
        addr = IPv4Address(value)
        first_octet = addr.packed[0]
        if first_octet < 128:
            prefix = 8
        elif first_octet < 192:
            prefix = 16
        else:
            prefix = 24
        return IPv4Network(f"{addr}/{prefix}", strict=False)

    # ------------------------------------------------------------------
    # OSPF ヘルパー
    # ------------------------------------------------------------------
    def enable_ospf(self, process_id: int) -> None:
        if process_id <= 0:
            raise ValueError("process-id must be positive")
        self.ospf_enabled = True
        self.ospf_process_id = process_id
        if self.ospf_router_id is None:
            self.ospf_router_id = self._auto_router_id()
        self._log(f"OSPF process {process_id} enabled")

    def disable_ospf(self) -> None:
        if self.ospf_enabled:
            self._log("OSPF disabled")
        self.ospf_enabled = False
        self.ospf_process_id = None
        self.ospf_router_id = None
        self.ospf_networks.clear()
        self.ospf_redistribute_static = False

    def set_ospf_router_id(self, router_id: str) -> None:
        if not _validate_ipv4(router_id):
            raise ValueError("invalid router-id")
        self.ospf_router_id = IPv4Address(router_id)
        self._log(f"OSPF router-id set to {router_id}")

    def add_ospf_network(self, ip: str, wildcard: str, area: str) -> None:
        if not (_validate_ipv4(ip) and _validate_ipv4(wildcard)):
            raise ValueError("invalid address or wildcard")
        try:
            area_id = int(area)
        except ValueError as exc:
            raise ValueError("area must be numeric") from exc
        wildcard_addr = IPv4Address(wildcard)
        mask_int = (~int(wildcard_addr)) & 0xFFFFFFFF
        mask = IPv4Address(mask_int)
        network = IPv4Network(f"{ip}/{mask.exploded}", strict=False)
        entry = OspfNetwork(network=network, wildcard=wildcard_addr, area=area_id)
        if entry in self.ospf_networks:
            self._log(f"OSPF network {entry.description()} already configured")
        else:
            self.ospf_networks.add(entry)
            self._log(f"OSPF network {entry.description()} added")

    def remove_ospf_network(self, ip: str, wildcard: str, area: str) -> None:
        if not (_validate_ipv4(ip) and _validate_ipv4(wildcard)):
            raise ValueError("invalid address or wildcard")
        try:
            area_id = int(area)
        except ValueError as exc:
            raise ValueError("area must be numeric") from exc
        wildcard_addr = IPv4Address(wildcard)
        mask_int = (~int(wildcard_addr)) & 0xFFFFFFFF
        mask = IPv4Address(mask_int)
        network = IPv4Network(f"{ip}/{mask.exploded}", strict=False)
        entry = OspfNetwork(network=network, wildcard=wildcard_addr, area=area_id)
        if entry not in self.ospf_networks:
            raise ValueError("OSPF network not found")
        self.ospf_networks.remove(entry)
        self._log(f"OSPF network {entry.description()} removed")

    def set_ospf_redistribute_static(self, enabled: bool) -> None:
        self.ospf_redistribute_static = enabled
        state = "enabled" if enabled else "disabled"
        self._log(f"OSPF redistribute static {state}")

    def show_ip_ospf_neighbor(self) -> str:
        if not self.ospf_enabled:
            return "% OSPF not enabled"
        return "\n".join(
            [
                "Neighbor ID     Pri   State           Dead Time   Address         Interface",
                "<none>"
                if not self.ospf_networks
                else "0.0.0.0         1     FULL/DR         00:00:38   0.0.0.0        Loopback0",
            ]
        )

    def show_ip_ospf_database(self) -> str:
        if not self.ospf_enabled:
            return "% OSPF not enabled"
        lines = [
            "            OSPF Router with ID ({}), Process ID {}".format(
                (self.ospf_router_id or self._auto_router_id()).exploded if self.ospf_router_id else "0.0.0.0",
                self.ospf_process_id or 1,
            )
        ]
        if not self.ospf_networks:
            lines.append("  <no LSAs>")
        else:
            for entry in sorted(self.ospf_networks, key=lambda e: (int(e.network.network_address), e.area)):
                lines.append(
                    f"  Net Link States (Area {entry.area})\n"
                    f"    Link ID: {entry.network.network_address.exploded}  Net Mask: {entry.network.netmask.exploded}"
                )
        return "\n".join(lines)

    def _auto_router_id(self) -> IPv4Address:
        candidate_ips = []
        for iface in self._interfaces.values():
            if iface.ip_address and _validate_ipv4(iface.ip_address):
                candidate_ips.append(IPv4Address(iface.ip_address))
        if self.static_routes:
            candidate_ips.extend(route.network.network_address for route in self.static_routes)
        if candidate_ips:
            return max(candidate_ips)
        return IPv4Address("1.1.1.1")

    # ------------------------------------------------------------------
    # BGP ヘルパー
    # ------------------------------------------------------------------
    def enable_bgp(self, asn: int) -> None:
        if asn <= 0:
            raise ValueError("AS number must be positive")
        if self.bgp_enabled and self.bgp_asn != asn:
            self.bgp_neighbors.clear()
            self.bgp_networks.clear()
        self.bgp_enabled = True
        self.bgp_asn = asn
        self._log(f"BGP process {asn} enabled")

    def disable_bgp(self) -> None:
        if self.bgp_enabled:
            self._log("BGP disabled")
        self.bgp_enabled = False
        self.bgp_asn = None
        self.bgp_neighbors.clear()
        self.bgp_networks.clear()
        self.bgp_redistribute_static = False

    def add_bgp_neighbor(self, address: str, remote_as: str) -> None:
        if not _validate_ipv4(address):
            raise ValueError("invalid neighbor address")
        try:
            remote_asn = int(remote_as)
        except ValueError as exc:
            raise ValueError("remote-as must be numeric") from exc
        neighbor = BgpNeighbor(address=IPv4Address(address), remote_as=remote_asn)
        self.bgp_neighbors[neighbor.address] = neighbor
        self._log(f"BGP neighbor {neighbor.description()} configured")

    def remove_bgp_neighbor(self, address: str) -> None:
        if not _validate_ipv4(address):
            raise ValueError("invalid neighbor address")
        addr = IPv4Address(address)
        if addr not in self.bgp_neighbors:
            raise ValueError("neighbor not found")
        del self.bgp_neighbors[addr]
        self._log(f"BGP neighbor {address} removed")

    def add_bgp_network(self, network: str, mask: str) -> None:
        if not (_validate_ipv4(network) and _validate_ipv4(mask)):
            raise ValueError("invalid network or mask")
        prefix = IPv4Network(f"{network}/{mask}", strict=False)
        entry = BgpNetwork(prefix=prefix)
        if entry in self.bgp_networks:
            self._log(f"BGP network {entry.description()} already exists")
        else:
            self.bgp_networks.add(entry)
            self._log(f"BGP network {entry.description()} advertised")

    def remove_bgp_network(self, network: str, mask: str) -> None:
        if not (_validate_ipv4(network) and _validate_ipv4(mask)):
            raise ValueError("invalid network or mask")
        prefix = IPv4Network(f"{network}/{mask}", strict=False)
        entry = BgpNetwork(prefix=prefix)
        if entry not in self.bgp_networks:
            raise ValueError("BGP network not found")
        self.bgp_networks.remove(entry)
        self._log(f"BGP network {entry.description()} withdrawn")

    def set_bgp_redistribute_static(self, enabled: bool) -> None:
        self.bgp_redistribute_static = enabled
        state = "enabled" if enabled else "disabled"
        self._log(f"BGP redistribute static {state}")

    # ------------------------------------------------------------------
    # NAT ヘルパー
    # ------------------------------------------------------------------
    def add_nat_pool(self, name: str, start: str, end: str, netmask: str) -> None:
        try:
            start_ip = IPv4Address(start)
            end_ip = IPv4Address(end)
            mask_ip = IPv4Address(netmask)
        except ValueError as exc:
            raise ValueError("invalid NAT pool addressing") from exc
        if int(start_ip) > int(end_ip):
            raise ValueError("pool start address must be <= end address")
        self.nat_pools[name] = NatPool(name=name, start=start_ip, end=end_ip, netmask=mask_ip)
        self._log(f"NAT pool {name} configured {start_ip}-{end_ip} netmask {mask_ip}")

    def remove_nat_pool(self, name: str) -> None:
        if name not in self.nat_pools:
            raise ValueError("NAT pool not found")
        del self.nat_pools[name]
        self.nat_mappings = [mapping for mapping in self.nat_mappings if mapping.pool != name]
        self._log(f"NAT pool {name} removed")

    def add_nat_mapping(self, access_list: str, pool: str, overload: bool) -> None:
        if pool not in self.nat_pools:
            raise ValueError("referenced NAT pool does not exist")
        mapping = NatMapping(access_list=access_list, pool=pool, overload=overload)
        if mapping in self.nat_mappings:
            self._log("NAT mapping already present")
            return
        self.nat_mappings.append(mapping)
        desc = "overload" if overload else ""
        self._log(f"NAT mapping list {access_list} -> pool {pool} {desc}".strip())

    def remove_nat_mapping(self, access_list: str, pool: str) -> None:
        target = NatMapping(access_list=access_list, pool=pool, overload=False)
        for existing in list(self.nat_mappings):
            if existing.access_list == access_list and existing.pool == pool:
                self.nat_mappings.remove(existing)
                self._log(f"NAT mapping list {access_list} -> pool {pool} removed")
                return
        raise ValueError("NAT mapping not found")

    def show_ip_nat_translations(self) -> str:
        lines = [
            "Pro  Inside global      Inside local       Outside local      Outside global",
            "<no active translations>",
            "",
            "NAT Pools:",
        ]
        if self.nat_pools:
            for pool in sorted(self.nat_pools.values(), key=lambda p: p.name.lower()):
                lines.append(
                    f"  {pool.name}: {pool.start.exploded}-{pool.end.exploded} netmask {pool.netmask.exploded}"
                )
        else:
            lines.append("  <none>")
        lines.append("")
        inside = [iface.name for iface in self._interfaces.values() if iface.nat_role == "inside"]
        outside = [iface.name for iface in self._interfaces.values() if iface.nat_role == "outside"]
        lines.append("Interface roles:")
        lines.append(f"  Inside: {', '.join(inside) if inside else '<none>'}")
        lines.append(f"  Outside: {', '.join(outside) if outside else '<none>'}")
        lines.append("")
        lines.append("Inside source mappings:")
        if self.nat_mappings:
            for mapping in self.nat_mappings:
                entry = f"  access-list {mapping.access_list} pool {mapping.pool}"
                if mapping.overload:
                    entry += " overload"
                lines.append(entry)
        else:
            lines.append("  <none>")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # ARP ヘルパー
    # ------------------------------------------------------------------
    def _add_arp_entry(self, ip: str, mac: str, interface: str, static: bool) -> None:
        self.arp_table[ip] = {
            "mac": mac.lower(),
            "interface": interface,
            "type": "ARPA",
            "static": static,
        }

    def add_dynamic_arp_entry(self, ip: str, mac: str, interface: str) -> None:
        if not (_validate_ipv4(ip)):
            raise ValueError("invalid IPv4 address")
        self._add_arp_entry(ip, mac, interface, static=False)
        self._log(f"ARP entry learned: {ip} -> {mac} on {interface}")

    def _remove_arp_entry(self, ip: str, interface: str) -> None:
        entry = self.arp_table.get(ip)
        if entry and entry.get("interface") == interface and entry.get("static", False):
            del self.arp_table[ip]

    def show_arp(self) -> str:
        for iface in self._interfaces.values():
            if iface.ip_address:
                self._add_arp_entry(iface.ip_address, iface.mac_address, iface.name, static=True)
        lines = [
            "Protocol  Address          Age (min)  Hardware Addr   Type   Interface",
        ]
        if not self.arp_table:
            lines.append("<no arp entries>")
            return "\n".join(lines)
        for ip in sorted(
            self.arp_table,
            key=lambda addr: tuple(int(part) for part in addr.split("."))
        ):
            entry = self.arp_table[ip]
            age = "-" if entry.get("static") else "0"
            lines.append(
                f"Internet  {ip:<16} {age:<9} {entry['mac']:<15} {entry['type']:<6} {entry['interface']}"
            )
        return "\n".join(lines)

    def clear_arp_cache(self) -> None:
        to_delete = [
            ip for ip, entry in self.arp_table.items() if not entry.get("static")
        ]
        for ip in to_delete:
            del self.arp_table[ip]
        self._log("ARP cache cleared")

    # ------------------------------------------------------------------
    # ログ管理
    # ------------------------------------------------------------------
    def _log(self, message: str) -> None:
        timestamp = ""
        if self.service_timestamps_enabled:
            timestamp = datetime.now(UTC).strftime("%H:%M:%S ")
        self.event_log.append(f"{timestamp}{message}")


class RouterCLI:
    """:class:`CiscoRouter` 用の簡易 CLI 実装。"""

    def __init__(self, router: CiscoRouter) -> None:
        self.router = router
        self._mode = "user_exec"  # user_exec | priv_exec | config | interface | router_rip | router_ospf | router_bgp
        self._current_interface: Optional[str] = None
        self._history: list[str] = []
        self._completion_matches: list[str] = []
        self._current_router_process: Optional[str] = None

    # ------------------------------------------------------------------
    # ユーティリティ
    # ------------------------------------------------------------------
    def _split_interface_token(self, name: str) -> tuple[str, str]:
        for index, char in enumerate(name):
            if char.isdigit():
                return name[:index], name[index:]
        return name, ""

    def _match_command(
        self,
        command: str,
        canonical: str,
        allow_suffix: bool = False,
    ) -> Optional[tuple[list[str], str]]:
        tokens = command.split()
        canonical_tokens = canonical.lower().split()
        if len(tokens) < len(canonical_tokens):
            return None
        for index, expected in enumerate(canonical_tokens):
            candidate = tokens[index].lower()
            if len(candidate) > len(expected) or not expected.startswith(candidate):
                return None
        remainder_tokens = tokens[len(canonical_tokens) :]
        if remainder_tokens and not allow_suffix:
            return None
        remainder_text = " ".join(remainder_tokens)
        return remainder_tokens, remainder_text

    def _command_templates_for_mode(self) -> list[list[str]]:
        if self._mode == "user_exec":
            return self._user_exec_commands()
        if self._mode == "priv_exec":
            return self._priv_exec_commands()
        if self._mode == "config":
            return self._config_commands()
        if self._mode == "interface":
            return self._interface_commands()
        if self._mode == "router_rip":
            return self._router_rip_commands()
        if self._mode == "router_ospf":
            return self._router_ospf_commands()
        if self._mode == "router_bgp":
            return self._router_bgp_commands()
        return []

    def _resolve_interface_name(self, alias: str) -> Optional[str]:
        alias = alias.strip()
        if not alias:
            return None
        interfaces = list(self.router._interfaces.keys())
        for name in interfaces:
            if name.lower() == alias.lower():
                return name

        alias_prefix, alias_suffix = self._split_interface_token(alias)
        if not alias_prefix:
            return None
        candidates: list[str] = []
        for name in interfaces:
            prefix, suffix = self._split_interface_token(name)
            if not prefix.lower().startswith(alias_prefix.lower()):
                continue
            if alias_suffix and not suffix.startswith(alias_suffix):
                continue
            candidates.append(name)
        if len(candidates) == 1:
            return candidates[0]
        return None

    def _user_exec_commands(self) -> list[list[str]]:
        return [
            ["enable"],
            ["exit"],
            ["quit"],
            ["logout"],
            ["help"],
            ["show", "interfaces"],
            ["show", "ip", "interface", "brief"],
            ["show", "ip", "nat", "translations"],
            ["show", "version"],
            ["show", "arp"],
            ["show", "ip", "protocols"],
        ]

    def _priv_exec_commands(self) -> list[list[str]]:
        cmds = self._user_exec_commands()
        cmds.extend(
            [
                ["disable"],
                ["configure", "terminal"],
                ["show", "startup-config"],
                ["show", "processes"],
                ["show", "users"],
                ["show", "ip", "route"],
                ["show", "ip", "protocols"],
                ["show", "running-config"],
                ["copy", "running-config", "startup-config"],
                ["copy", "run", "start"],
                ["write", "memory"],
                ["reload"],
                ["exit"],
                ["logout"],
            ]
        )
        return cmds

    def _config_commands(self) -> list[list[str]]:
        return [
            ["exit"],
            ["end"],
            ["help"],
            ["hostname", "<text>"],
            ["enable", "secret", "<password>"],
            ["service", "timestamps", "log", "datetime"],
            ["no", "service", "timestamps", "log", "datetime"],
            ["interface", "<interface>"],
            ["service", "password-encryption"],
            ["no", "service", "password-encryption"],
            ["ip", "domain-lookup"],
            ["no", "ip", "domain-lookup"],
            ["ip", "name-server", "<ip>"],
            ["no", "ip", "name-server"],
            ["banner", "motd", "<banner>"] ,
            ["no", "banner", "motd"],
            ["clock", "timezone", "<zone>", "<offset>"],
            ["vlan", "<vlan>"],
            ["no", "vlan", "<vlan>"],
            ["ip", "route", "<ip>", "<mask>", "<next-hop>"],
            ["no", "ip", "route", "<ip>", "<mask>", "<next-hop>"],
            ["router", "rip"],
            ["no", "router", "rip"],
            ["router", "ospf", "<process>"],
            ["no", "router", "ospf"],
            ["router", "bgp", "<asn>"],
            ["no", "router", "bgp"],
            ["ip", "nat", "pool", "<nat_pool>", "<ip>", "<ip>", "netmask", "<mask>"],
            ["no", "ip", "nat", "pool", "<nat_pool>"],
            ["ip", "nat", "inside", "source", "list", "<acl>", "pool", "<nat_pool>", "overload"],
            ["ip", "nat", "inside", "source", "list", "<acl>", "pool", "<nat_pool>"],
            ["no", "ip", "nat", "inside", "source", "list", "<acl>", "pool", "<nat_pool>"],
        ]

    def _interface_commands(self) -> list[list[str]]:
        return [
            ["exit"],
            ["end"],
            ["help"],
            ["ip", "address", "<ip>", "<mask>"],
            ["no", "ip", "address"],
            ["shutdown"],
            ["no", "shutdown"],
            ["description", "<text>"],
            ["ip", "nat", "inside"],
            ["ip", "nat", "outside"],
            ["no", "ip", "nat", "inside"],
            ["no", "ip", "nat", "outside"],
        ]

    def _router_rip_commands(self) -> list[list[str]]:
        return [
            ["exit"],
            ["end"],
            ["help"],
            ["version", "<version>"],
            ["network", "<network>"],
            ["no", "network", "<network>"],
            ["auto-summary"],
            ["no", "auto-summary"],
            ["redistribute", "static"],
            ["no", "redistribute", "static"],
        ]

    def _router_ospf_commands(self) -> list[list[str]]:
        return [
            ["exit"],
            ["end"],
            ["help"],
            ["router-id", "<ip>"],
            ["network", "<ip>", "<wildcard>", "area", "<area>"],
            ["no", "network", "<ip>", "<wildcard>", "area", "<area>"],
            ["redistribute", "static"],
            ["no", "redistribute", "static"],
        ]

    def _router_bgp_commands(self) -> list[list[str]]:
        return [
            ["exit"],
            ["end"],
            ["help"],
            ["neighbor", "<neighbor>", "remote-as", "<remote-as>"],
            ["no", "neighbor", "<neighbor>"],
            ["network", "<ip>", "mask", "<mask>"],
            ["no", "network", "<ip>", "mask", "<mask>"],
            ["redistribute", "static"],
            ["no", "redistribute", "static"],
        ]

    def complete(self, text: str, state: int) -> Optional[str]:
        if state == 0:
            buffer = ""
            try:
                import readline  # 遅延インポート
            except ImportError:
                return None
            buffer = readline.get_line_buffer()
            if buffer.endswith(" "):
                buffer_tokens = buffer.split()
                buffer_tokens.append("")
            self._completion_matches = self._collect_completion_candidates(buffer, text)
        if state < len(self._completion_matches):
            return self._completion_matches[state]
        return None

    def _collect_completion_candidates(self, buffer: str, text: str) -> list[str]:
        tokens = buffer.split()
        if buffer.endswith(" "):
            tokens.append("")
        prefix_tokens = tokens[:-1] if tokens else []
        fragment = tokens[-1] if tokens else ""
        commands = self._command_templates_for_mode()
        matches: set[str] = set()
        fragment_lower = fragment.lower()
        for template in commands:
            if len(prefix_tokens) > len(template):
                continue
            valid = True
            for index, token in enumerate(prefix_tokens):
                tmpl = template[index]
                if self._is_placeholder(tmpl):
                    continue
                if not tmpl.startswith(token.lower()):
                    valid = False
                    break
            if not valid:
                continue
            if len(template) <= len(prefix_tokens):
                continue
            candidate = template[len(prefix_tokens)]
            values = self._placeholder_values(candidate) if self._is_placeholder(candidate) else [candidate]
            for value in values:
                if value.lower().startswith(fragment_lower):
                    matches.add(value)
        return sorted(matches)

    @staticmethod
    def _is_placeholder(token: str) -> bool:
        return token.startswith("<") and token.endswith(">")

    def _placeholder_values(self, placeholder: str) -> list[str]:
        if placeholder == "<interface>":
            return sorted(self.router._interfaces.keys())
        if placeholder == "<ip>":
            suggestions = [ns.exploded for ns in self.router.name_servers]
            if suggestions:
                return suggestions
            return ["192.168.1.1"]
        if placeholder == "<mask>":
            return ["255.255.255.0"]
        if placeholder == "<password>":
            return []
        if placeholder == "<banner>":
            return []
        if placeholder == "<zone>":
            return ["JST"]
        if placeholder == "<offset>":
            return ["9"]
        if placeholder == "<vlan>":
            vlans = sorted(self.router.vlans) or ["10"]
            return [str(v) for v in vlans]
        if placeholder == "<next-hop>":
            return ["192.168.1.1"]
        if placeholder == "<version>":
            return ["1", "2"]
        if placeholder == "<network>":
            networks = [n.network_address.exploded for n in self.router.rip_networks]
            return networks or ["192.168.1.0"]
        if placeholder == "<process>":
            return [str(self.router.ospf_process_id or 1)]
        if placeholder == "<wildcard>":
            return ["0.0.0.255"]
        if placeholder == "<area>":
            areas = {n.area for n in self.router.ospf_networks}
            return [str(area) for area in sorted(areas)] or ["0"]
        if placeholder == "<asn>":
            return [str(self.router.bgp_asn or 65000)]
        if placeholder == "<neighbor>":
            return [addr.exploded for addr in self.router.bgp_neighbors] or ["192.0.2.1"]
        if placeholder == "<remote-as>":
            return [str(neighbor.remote_as) for neighbor in self.router.bgp_neighbors.values()] or ["65001"]
        if placeholder == "<nat_pool>":
            return sorted(self.router.nat_pools.keys()) or ["POOL1"]
        if placeholder == "<acl>":
            lists = {mapping.access_list for mapping in self.router.nat_mappings}
            return [acl for acl in sorted(lists)] or ["1"]
        return []

    def _parse_banner(self, text: str) -> Optional[str]:
        text = text.lstrip()
        if not text:
            return None
        delimiter = text[0]
        if delimiter == "":
            return None
        parts = text.split(delimiter)
        if len(parts) < 3:
            return None
        message = delimiter.join(parts[1:-1])
        return message

    # ------------------------------------------------------------------
    # CLI エントリポイント
    # ------------------------------------------------------------------
    def execute(self, command: str) -> str:
        command = command.strip()
        if not command:
            return ""
        self._history.append(command)
        if len(self._history) > 20:
            self._history = self._history[-20:]

        if self._mode == "user_exec":
            return self._handle_user_exec(command)
        if self._mode == "priv_exec":
            return self._handle_priv_exec(command)
        if self._mode == "config":
            return self._handle_config(command)
        if self._mode == "interface":
            return self._handle_interface(command)
        if self._mode == "router_rip":
            return self._handle_router_rip(command)
        if self._mode == "router_ospf":
            return self._handle_router_ospf(command)
        if self._mode == "router_bgp":
            return self._handle_router_bgp(command)
        raise RuntimeError(f"invalid CLI mode: {self._mode}")

    def _handle_user_exec(self, command: str) -> str:
        if self._match_command(command, "enable") is not None:
            self._mode = "priv_exec"
            return ""
        match = self._match_command(command, "ping", allow_suffix=True)
        if match is not None:
            remainder_tokens, remainder_text = match
            tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
            if len(tokens) != 1:
                return "Usage: ping <ip-address>"
            return self.router.ping(tokens[0])
        match = self._match_command(command, "traceroute", allow_suffix=True)
        if match is not None:
            remainder_tokens, remainder_text = match
            tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
            if len(tokens) != 1:
                return "Usage: traceroute <ip-address>"
            return self.router.traceroute(tokens[0])
        if self._match_command(command, "exit") is not None:
            return "Session closed."
        if self._match_command(command, "logout") is not None:
            return "Session closed."
        shared = self._handle_show(command)
        if shared is not None:
            return shared
        return "% Command available in privileged EXEC mode."

    def _handle_priv_exec(self, command: str) -> str:
        if self._match_command(command, "disable") is not None:
            self._mode = "user_exec"
            return ""
        if self._match_command(command, "configure terminal") is not None:
            self._mode = "config"
            return "Enter configuration commands, one per line. End with CNTL/Z."
        match = self._match_command(command, "ping", allow_suffix=True)
        if match is not None:
            remainder_tokens, remainder_text = match
            tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
            if len(tokens) != 1:
                return "Usage: ping <ip-address>"
            return self.router.ping(tokens[0])
        match = self._match_command(command, "traceroute", allow_suffix=True)
        if match is not None:
            remainder_tokens, remainder_text = match
            tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
            if len(tokens) != 1:
                return "Usage: traceroute <ip-address>"
            return self.router.traceroute(tokens[0])
        if self._match_command(command, "exit") is not None:
            self._mode = "user_exec"
            return ""
        if self._match_command(command, "logout") is not None:
            self._mode = "user_exec"
            return ""
        if self._match_command(command, "show startup-config") is not None:
            return self.router.show_startup_config()
        if self._match_command(command, "show processes") is not None:
            return self.router.show_processes()
        if self._match_command(command, "show users") is not None:
            return self.router.show_users()
        if self._match_command(command, "show ip route") is not None:
            return self.router.show_ip_route()
        if self._match_command(command, "show ip ospf neighbor") is not None:
            return self.router.show_ip_ospf_neighbor()
        if self._match_command(command, "show ip ospf database") is not None:
            return self.router.show_ip_ospf_database()
        if self._match_command(command, "show ip bgp") is not None:
            return self.router.show_ip_bgp()
        if self._match_command(command, "show running-config") is not None:
            return self.router.show_running_config()
        shared = self._handle_show(command)
        if shared is not None:
            return shared
        if self._match_command(command, "copy running-config startup-config", allow_suffix=True) is not None:
            self.router.save_startup_config()
            return "Building configuration...\n[OK]"
        if self._match_command(command, "copy run start", allow_suffix=True) is not None:
            self.router.save_startup_config()
            return "Building configuration...\n[OK]"
        if self._match_command(command, "write memory", allow_suffix=True) is not None:
            self.router.save_startup_config()
            return "Building configuration...\n[OK]"
        if self._match_command(command, "reload") is not None:
            message = self.router.reload()
            self._mode = "user_exec"
            return message
        if self._match_command(command, "clear arp-cache") is not None:
            self.router.clear_arp_cache()
            return "ARP cache cleared"
        return f"% Unknown command: {command}"

    def _handle_config(self, command: str) -> str:
        if self._match_command(command, "exit") is not None:
            self._mode = "priv_exec"
            return ""
        if self._match_command(command, "end") is not None:
            self._mode = "priv_exec"
            return ""
        match = self._match_command(command, "hostname", allow_suffix=True)
        if match is not None:
            _, remainder = match
            if not remainder:
                return "Usage: hostname <name>"
            try:
                self.router.set_hostname(remainder)
            except ValueError as exc:
                return f"% {exc}"
            return ""
        match = self._match_command(command, "enable secret", allow_suffix=True)
        if match is not None:
            _, remainder = match
            if not remainder:
                return "Usage: enable secret <password>"
            try:
                self.router.set_enable_secret(remainder)
            except ValueError as exc:
                return f"% {exc}"
            return ""
        if self._match_command(command, "service password-encryption") is not None:
            self.router.set_password_encryption(True)
            return ""
        if self._match_command(command, "no service password-encryption") is not None:
            self.router.set_password_encryption(False)
            return ""
        if self._match_command(command, "no ip domain-lookup") is not None:
            self.router.set_domain_lookup(False)
            return ""
        if self._match_command(command, "ip domain-lookup") is not None:
            self.router.set_domain_lookup(True)
            return ""
        match = self._match_command(command, "ip name-server", allow_suffix=True)
        if match is not None:
            remainder_tokens, remainder_text = match
            tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
            if not tokens:
                return "Usage: ip name-server <address> [address ...]"
            try:
                self.router.set_name_servers(tokens)
            except ValueError as exc:
                return f"% {exc}"
            return ""
        match = self._match_command(command, "no ip name-server", allow_suffix=True)
        if match is not None:
            remainder_tokens, remainder_text = match
            tokens = remainder_tokens if remainder_tokens else (
                remainder_text.split() if remainder_text else []
            )
            try:
                self.router.remove_name_servers(tokens if tokens else None)
            except ValueError as exc:
                return f"% {exc}"
            return ""
        match = self._match_command(command, "banner motd", allow_suffix=True)
        if match is not None:
            _, remainder = match
            if not remainder:
                return "Usage: banner motd #text#"
            message = self._parse_banner(remainder)
            if message is None:
                return "Usage: banner motd #text#"
            self.router.set_banner_motd(message)
            return ""
        if self._match_command(command, "no banner motd") is not None:
            self.router.set_banner_motd(None)
            return ""
        match = self._match_command(command, "clock timezone", allow_suffix=True)
        if match is not None:
            remainder_tokens, _ = match
            if len(remainder_tokens) != 2:
                return "Usage: clock timezone <zone> <offset>"
            zone, offset_str = remainder_tokens
            try:
                offset = int(offset_str)
            except ValueError:
                return "% Offset must be numeric"
            self.router.set_clock_timezone(zone, offset)
            return ""
        if self._match_command(command, "router rip") is not None:
            self.router.enable_rip()
            self._mode = "router_rip"
            self._current_router_process = "rip"
            return "Enter RIP configuration commands. End with CNTL/Z."
        if self._match_command(command, "no router rip") is not None:
            self.router.disable_rip()
            self._current_router_process = None
            return ""
        match = self._match_command(command, "router ospf", allow_suffix=True)
        if match is not None:
            remainder_tokens, remainder_text = match
            tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
            if len(tokens) != 1:
                return "Usage: router ospf <process-id>"
            try:
                process_id = int(tokens[0])
            except ValueError:
                return "% Process-id must be numeric"
            try:
                self.router.enable_ospf(process_id)
            except ValueError as exc:
                return f"% {exc}"
            self._mode = "router_ospf"
            self._current_router_process = "ospf"
            return "Enter OSPF configuration commands. End with CNTL/Z."
        if self._match_command(command, "no router ospf") is not None:
            self.router.disable_ospf()
            self._current_router_process = None
            return ""
        match = self._match_command(command, "router bgp", allow_suffix=True)
        if match is not None:
            remainder_tokens, remainder_text = match
            tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
            if len(tokens) != 1:
                return "Usage: router bgp <asn>"
            try:
                asn = int(tokens[0])
            except ValueError:
                return "% AS number must be numeric"
            try:
                self.router.enable_bgp(asn)
            except ValueError as exc:
                return f"% {exc}"
            self._mode = "router_bgp"
            self._current_router_process = "bgp"
            return "Enter BGP configuration commands. End with CNTL/Z."
        if self._match_command(command, "no router bgp", allow_suffix=True) is not None:
            self.router.disable_bgp()
            if self._mode == "config":
                self._current_router_process = None
                return ""
        match = self._match_command(command, "vlan", allow_suffix=True)
        if match is not None:
            remainder_tokens, _ = match
            if len(remainder_tokens) != 1:
                return "Usage: vlan <id>"
            try:
                vlan = int(remainder_tokens[0])
            except ValueError:
                return "% VLAN must be numeric"
            try:
                self.router.create_vlan(vlan)
            except ValueError as exc:
                return f"% {exc}"
            return ""
        match = self._match_command(command, "no vlan", allow_suffix=True)
        if match is not None:
            remainder_tokens, _ = match
            if len(remainder_tokens) != 1:
                return "Usage: no vlan <id>"
            try:
                vlan = int(remainder_tokens[0])
            except ValueError:
                return "% VLAN must be numeric"
            try:
                self.router.delete_vlan(vlan)
            except ValueError as exc:
                return f"% {exc}"
            return ""
        match = self._match_command(command, "ip route", allow_suffix=True)
        if match is not None:
            remainder_tokens, _ = match
            if len(remainder_tokens) != 3:
                return "Usage: ip route <destination> <mask> <next-hop>"
            destination, mask, next_hop = remainder_tokens
            try:
                self.router.add_static_route(destination, mask, next_hop)
            except ValueError as exc:
                return f"% {exc}"
            return ""
        match = self._match_command(command, "no ip route", allow_suffix=True)
        if match is not None:
            remainder_tokens, _ = match
            if len(remainder_tokens) != 3:
                return "Usage: no ip route <destination> <mask> <next-hop>"
            destination, mask, next_hop = remainder_tokens
            try:
                self.router.remove_static_route(destination, mask, next_hop)
            except ValueError as exc:
                return f"% {exc}"
            return ""
        match = self._match_command(command, "ip nat pool", allow_suffix=True)
        if match is not None:
            remainder_tokens, remainder_text = match
            tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
            if len(tokens) != 5 or tokens[3].lower() != "netmask":
                return "Usage: ip nat pool <name> <start-ip> <end-ip> netmask <mask>"
            name, start, end, _, mask = tokens
            try:
                self.router.add_nat_pool(name, start, end, mask)
            except ValueError as exc:
                return f"% {exc}"
            return ""
        match = self._match_command(command, "no ip nat pool", allow_suffix=True)
        if match is not None:
            remainder_tokens, remainder_text = match
            tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
            if len(tokens) != 1:
                return "Usage: no ip nat pool <name>"
            try:
                self.router.remove_nat_pool(tokens[0])
            except ValueError as exc:
                return f"% {exc}"
            return ""
        match = self._match_command(command, "ip nat inside source list", allow_suffix=True)
        if match is not None:
            remainder_tokens, remainder_text = match
            tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
            if len(tokens) not in {3, 4} or tokens[1].lower() != "pool":
                return "Usage: ip nat inside source list <list> pool <name> [overload]"
            access_list = tokens[0]
            pool = tokens[2]
            overload = len(tokens) == 4 and tokens[3].lower() == "overload"
            try:
                self.router.add_nat_mapping(access_list, pool, overload)
            except ValueError as exc:
                return f"% {exc}"
            return ""
        match = self._match_command(command, "no ip nat inside source list", allow_suffix=True)
        if match is not None:
            remainder_tokens, remainder_text = match
            tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
            if len(tokens) != 3 or tokens[1].lower() != "pool":
                return "Usage: no ip nat inside source list <list> pool <name>"
            access_list = tokens[0]
            pool = tokens[2]
            try:
                self.router.remove_nat_mapping(access_list, pool)
            except ValueError as exc:
                return f"% {exc}"
            return ""
        if self._match_command(command, "service timestamps log datetime") is not None:
            self.router.set_service_timestamps(True)
            return ""
        if self._match_command(command, "no service timestamps log datetime") is not None:
            self.router.set_service_timestamps(False)
            return ""
        match = self._match_command(command, "interface", allow_suffix=True)
        if match is not None:
            remainder_tokens, remainder_text = match
            if not remainder_tokens and not remainder_text:
                return "Usage: interface <name>"
            candidate = remainder_text or remainder_tokens[0]
            resolved = self._resolve_interface_name(candidate)
            if resolved is None:
                return f"% unknown interface: {candidate}"
            self._current_interface = resolved
            self._mode = "interface"
            return f"Enter configuration commands for {resolved}. End with CNTL/Z."
        return f"% Unknown configuration command: {command}"

    def _handle_interface(self, command: str) -> str:
        if self._match_command(command, "exit") is not None:
            self._mode = "config"
            self._current_interface = None
            return ""
        if self._match_command(command, "end") is not None:
            self._mode = "priv_exec"
            self._current_interface = None
            return ""
        if not self._current_interface:
            return "% No interface selected"
        iface = self._current_interface
        if self._match_command(command, "shutdown") is not None:
            self.router.set_interface_admin_state(iface, False)
            return ""
        if self._match_command(command, "no shutdown") is not None:
            self.router.set_interface_admin_state(iface, True)
            return ""
        if self._match_command(command, "ip nat inside") is not None:
            self.router.set_interface_nat_role(iface, "inside")
            return ""
        if self._match_command(command, "ip nat outside") is not None:
            self.router.set_interface_nat_role(iface, "outside")
            return ""
        if self._match_command(command, "no ip nat inside") is not None:
            self.router.clear_interface_nat_role(iface, "inside")
            return ""
        if self._match_command(command, "no ip nat outside") is not None:
            self.router.clear_interface_nat_role(iface, "outside")
            return ""
        match = self._match_command(command, "ip address", allow_suffix=True)
        if match is not None:
            remainder_tokens, _ = match
            if len(remainder_tokens) != 2:
                return "Usage: ip address <address> <mask>"
            ip, mask = remainder_tokens
            try:
                self.router.set_interface_ip(iface, ip, mask)
            except ValueError as exc:
                return f"% {exc}"
            return ""
        if self._match_command(command, "no ip address") is not None:
            self.router.clear_interface_ip(iface)
            return ""
        match = self._match_command(command, "description", allow_suffix=True)
        if match is not None:
            _, remainder = match
            self.router.set_interface_description(iface, remainder)
            return ""
        return f"% Unknown interface command: {command}"

    def _handle_router_rip(self, command: str) -> str:
        if self._match_command(command, "exit") is not None:
            self._mode = "config"
            self._current_router_process = None
            return ""
        if self._match_command(command, "end") is not None:
            self._mode = "priv_exec"
            self._current_router_process = None
            return ""
        if self._match_command(command, "no router rip") is not None:
            self.router.disable_rip()
            self._mode = "config"
            self._current_router_process = None
            return ""
        if not self.router.rip_enabled:
            return "% RIP is not enabled"
        match = self._match_command(command, "version", allow_suffix=True)
        if match is not None:
            remainder_tokens, remainder_text = match
            tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
            if len(tokens) != 1:
                return "Usage: version <1|2>"
            try:
                version = int(tokens[0])
            except ValueError:
                return "% Version must be numeric"
            try:
                self.router.set_rip_version(version)
            except ValueError as exc:
                return f"% {exc}"
            return ""
        match = self._match_command(command, "network", allow_suffix=True)
        if match is not None:
            remainder_tokens, remainder_text = match
            tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
            if len(tokens) != 1:
                return "Usage: network <address>"
            try:
                self.router.add_rip_network(tokens[0])
            except ValueError as exc:
                return f"% {exc}"
            return ""
        match = self._match_command(command, "no network", allow_suffix=True)
        if match is not None:
            remainder_tokens, remainder_text = match
            tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
            if len(tokens) != 1:
                return "Usage: no network <address>"
            try:
                self.router.remove_rip_network(tokens[0])
            except ValueError as exc:
                return f"% {exc}"
            return ""
        if self._match_command(command, "no auto-summary") is not None:
            self.router.set_rip_auto_summary(False)
            return ""
        if self._match_command(command, "auto-summary") is not None:
            self.router.set_rip_auto_summary(True)
            return ""
        if self._match_command(command, "redistribute static") is not None:
            self.router.set_rip_redistribute_static(True)
            return ""
        if self._match_command(command, "no redistribute static") is not None:
            self.router.set_rip_redistribute_static(False)
            return ""
        if command == "help":
            return (
                "RIP configuration commands:\n"
                "  network <address>\n"
                "  no network <address>\n"
                "  version <1|2>\n"
                "  no auto-summary | auto-summary\n"
                "  exit | end"
            )
        return f"% Unknown RIP command: {command}"

    def _handle_router_ospf(self, command: str) -> str:
        if self._match_command(command, "exit") is not None:
            self._mode = "config"
            self._current_router_process = None
            return ""
        if self._match_command(command, "end") is not None:
            self._mode = "priv_exec"
            self._current_router_process = None
            return ""
        if self._match_command(command, "no router ospf") is not None:
            self.router.disable_ospf()
            self._mode = "config"
            self._current_router_process = None
            return ""
        if not self.router.ospf_enabled:
            return "% OSPF is not enabled"
        match = self._match_command(command, "router-id", allow_suffix=True)
        if match is not None:
            remainder_tokens, remainder_text = match
            tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
            if len(tokens) != 1:
                return "Usage: router-id <ip>"
            try:
                self.router.set_ospf_router_id(tokens[0])
            except ValueError as exc:
                return f"% {exc}"
            return ""
        match = self._match_command(command, "network", allow_suffix=True)
        if match is not None:
            remainder_tokens, remainder_text = match
            tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
            if len(tokens) != 4 or tokens[2].lower() != "area":
                return "Usage: network <ip> <wildcard> area <id>"
            ip_addr, wildcard, _, area = tokens
            try:
                self.router.add_ospf_network(ip_addr, wildcard, area)
            except ValueError as exc:
                return f"% {exc}"
            return ""
        match = self._match_command(command, "no network", allow_suffix=True)
        if match is not None:
            remainder_tokens, remainder_text = match
            tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
            if len(tokens) != 4 or tokens[2].lower() != "area":
                return "Usage: no network <ip> <wildcard> area <id>"
            ip_addr, wildcard, _, area = tokens
            try:
                self.router.remove_ospf_network(ip_addr, wildcard, area)
            except ValueError as exc:
                return f"% {exc}"
            return ""
        if self._match_command(command, "redistribute static") is not None:
            self.router.set_ospf_redistribute_static(True)
            return ""
        if self._match_command(command, "no redistribute static") is not None:
            self.router.set_ospf_redistribute_static(False)
            return ""
        if command == "help":
            return (
                "OSPF configuration commands:\n"
                "  router-id <ip>\n"
                "  network <ip> <wildcard> area <id>\n"
                "  no network <ip> <wildcard> area <id>\n"
                "  redistribute static | no redistribute static\n"
                "  exit | end"
            )
        return f"% Unknown OSPF command: {command}"

    def _handle_router_bgp(self, command: str) -> str:
        if self._match_command(command, "exit") is not None:
            self._mode = "config"
            self._current_router_process = None
            return ""
        if self._match_command(command, "end") is not None:
            self._mode = "priv_exec"
            self._current_router_process = None
            return ""
        if self._match_command(command, "no router bgp") is not None:
            self.router.disable_bgp()
            self._mode = "config"
            self._current_router_process = None
            return ""
        if not self.router.bgp_enabled:
            return "% BGP is not enabled"
        match = self._match_command(command, "neighbor", allow_suffix=True)
        if match is not None:
            remainder_tokens, remainder_text = match
            tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
            if len(tokens) != 3 or tokens[1].lower() != "remote-as":
                return "Usage: neighbor <ip> remote-as <asn>"
            ip_addr, _, remote_as = tokens
            try:
                self.router.add_bgp_neighbor(ip_addr, remote_as)
            except ValueError as exc:
                return f"% {exc}"
            return ""
        match = self._match_command(command, "no neighbor", allow_suffix=True)
        if match is not None:
            remainder_tokens, remainder_text = match
            tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
            if len(tokens) != 1:
                return "Usage: no neighbor <ip>"
            try:
                self.router.remove_bgp_neighbor(tokens[0])
            except ValueError as exc:
                return f"% {exc}"
            return ""
        match = self._match_command(command, "network", allow_suffix=True)
        if match is not None:
            remainder_tokens, remainder_text = match
            tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
            if len(tokens) != 3 or tokens[1].lower() != "mask":
                return "Usage: network <ip> mask <mask>"
            ip, _, mask = tokens
            try:
                self.router.add_bgp_network(ip, mask)
            except ValueError as exc:
                return f"% {exc}"
            return ""
        match = self._match_command(command, "no network", allow_suffix=True)
        if match is not None:
            remainder_tokens, remainder_text = match
            tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
            if len(tokens) != 3 or tokens[1].lower() != "mask":
                return "Usage: no network <ip> mask <mask>"
            ip, _, mask = tokens
            try:
                self.router.remove_bgp_network(ip, mask)
            except ValueError as exc:
                return f"% {exc}"
            return ""
        if self._match_command(command, "redistribute static") is not None:
            self.router.set_bgp_redistribute_static(True)
            return ""
        if self._match_command(command, "no redistribute static") is not None:
            self.router.set_bgp_redistribute_static(False)
            return ""
        if command == "help":
            return (
                "BGP configuration commands:\n"
                "  neighbor <ip> remote-as <asn>\n"
                "  no neighbor <ip>\n"
                "  network <ip> mask <mask>\n"
                "  no network <ip> mask <mask>\n"
                "  redistribute static | no redistribute static\n"
                "  exit | end"
            )
        return f"% Unknown BGP command: {command}"

    def _handle_show(self, command: str) -> Optional[str]:
        if self._match_command(command, "show arp") is not None:
            return self.router.show_arp()
        if self._match_command(command, "show interfaces") is not None:
            return self.router.show_interfaces()
        if self._match_command(command, "show ip interface brief") is not None:
            return self.router.show_ip_interface_brief()
        if self._match_command(command, "show ip ospf neighbor") is not None:
            return self.router.show_ip_ospf_neighbor()
        if self._match_command(command, "show ip ospf database") is not None:
            return self.router.show_ip_ospf_database()
        if self._match_command(command, "show ip bgp") is not None:
            return self.router.show_ip_bgp()
        if self._match_command(command, "show ip nat translations") is not None:
            return self.router.show_ip_nat_translations()
        if self._match_command(command, "show ip protocols") is not None:
            return self.router.show_ip_protocols()
        if self._match_command(command, "show version") is not None:
            return self.router.show_version()
        return None


def _default_router() -> CiscoRouter:
    iface_names = [f"GigabitEthernet0/{i}" for i in range(2)]
    return CiscoRouter(name="Router1", interfaces=iface_names)


def _repl(cli: RouterCLI) -> None:
    try:
        import readline
    except ImportError:
        readline = None

    if readline is not None:
        try:
            readline.parse_and_bind("tab: complete")
            readline.set_completer(lambda text, state: cli.complete(text, state))
            readline.set_completer_delims(" \t\n")
        except Exception:
            pass

    print("Simple router CLI. Type 'quit' to exit.")
    while True:
        hostname = cli.router.name
        if cli._mode == "user_exec":
            prompt = f"{hostname}> "
        elif cli._mode == "priv_exec":
            prompt = f"{hostname}# "
        elif cli._mode == "config":
            prompt = f"{hostname}(config)# "
        elif cli._mode in {"router_rip", "router_ospf", "router_bgp"}:
            prompt = f"{hostname}(config-router)# "
        else:
            prompt = f"{hostname}(config-if)# "
        try:
            command = input(prompt)
        except EOFError:
            print()
            break
        command = command.strip()
        if command in {"quit", "exit"} and cli._mode == "user_exec":
            break
        if command == "help":
            print(
                "Available commands:\n"
                "  show interfaces\n"
                "  show ip interface brief\n"
                "  show version\n"
                "  show running-config (privileged)\n"
                "  configure terminal\n"
            )
            continue
        output = cli.execute(command)
        if output:
            print(output)


if __name__ == "__main__":  # pragma: no cover - 手動実行用
    router = _default_router()
    cli = RouterCLI(router)
    _repl(cli)
