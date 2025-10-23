"""Core logic and data structures for the educational Cisco router simulator."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
from ipaddress import IPv4Address, IPv4Network, IPv4Interface
from typing import Dict, Iterable, Optional

from router_sim.static_route import StaticRoute
from router_sim.ospf import OspfNetwork
from router_sim.bgp import BgpNeighbor, BgpNetwork


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
        self.static_route_entries: list[tuple[str, str, str]] = []
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

    def set_interface_admin_state(self, interface: str, up: bool) -> None:
        iface = self._require_interface(interface)
        iface.admin_up = up
        state = "up" if up else "down"
        self._log(f"{interface} administratively {state}")

    def set_interface_description(self, interface: str, description: str) -> None:
        iface = self._require_interface(interface)
        iface.description = description
        self._log(f"{interface} description set to '{description}'")

    def set_interface_nat_role(self, interface: str, role: str) -> None:
        if role not in {"inside", "outside"}:
            raise ValueError("invalid NAT role")
        iface = self._require_interface(interface)
        iface.nat_role = role
        self._log(f"{interface} NAT role set to {role}")

    def clear_interface_nat_role(self, interface: str, role: str) -> None:
        iface = self._require_interface(interface)
        if iface.nat_role == role:
            iface.nat_role = "none"
            self._log(f"{interface} NAT role cleared from {role}")

    # ------------------------------------------------------------------
    # DNS
    # ------------------------------------------------------------------
    def set_name_servers(self, servers: Iterable[str]) -> None:
        converted: list[IPv4Address] = []
        for server in servers:
            if not _validate_ipv4(server):
                raise ValueError(f"invalid name server: {server}")
            converted.append(IPv4Address(server))
        self.name_servers = converted
        self._log(f"Name servers set: {', '.join(server.exploded for server in converted)}")

    def remove_name_servers(self, servers: Optional[Iterable[str]]) -> None:
        if servers is None:
            self.name_servers = []
            self._log("All name servers removed")
            return
        converted = {IPv4Address(server) for server in servers}
        before = len(self.name_servers)
        self.name_servers = [ns for ns in self.name_servers if ns not in converted]
        after = len(self.name_servers)
        if before != after:
            self._log("Selected name servers removed")
        else:
            self._log("No matching name servers found")

    # ------------------------------------------------------------------
    # ドメインルックアップ
    # ------------------------------------------------------------------
    def set_domain_lookup(self, enabled: bool) -> None:
        self.domain_lookup_enabled = enabled
        state = "enabled" if enabled else "disabled"
        self._log(f"Domain lookup {state}")

    # ------------------------------------------------------------------
    # パスワード暗号化
    # ------------------------------------------------------------------
    def set_password_encryption(self, enabled: bool) -> None:
        self.password_encryption = enabled
        state = "enabled" if enabled else "disabled"
        self._log(f"Password encryption {state}")

    # ------------------------------------------------------------------
    # MOTD バナー
    # ------------------------------------------------------------------
    def set_banner_motd(self, message: Optional[str]) -> None:
        if message:
            self.banner_motd = message
            self._log("MOTD banner configured")
        else:
            self.banner_motd = None
            self._log("MOTD banner cleared")

    # ------------------------------------------------------------------
    # タイムゾーン
    # ------------------------------------------------------------------
    def set_clock_timezone(self, name: str, offset: int) -> None:
        self.clock_timezone = (name, offset)
        self._log(f"Clock timezone set to {name} {offset}")

    # ------------------------------------------------------------------
    # VLAN
    # ------------------------------------------------------------------
    def create_vlan(self, vlan: int) -> None:
        if not (1 <= vlan <= 4094):
            raise ValueError("VLAN must be between 1 and 4094")
        self.vlans.add(vlan)
        self._log(f"VLAN {vlan} created")

    def delete_vlan(self, vlan: int) -> None:
        if vlan in self.vlans:
            self.vlans.remove(vlan)
            self._log(f"VLAN {vlan} deleted")
        else:
            raise ValueError("VLAN does not exist")

    # ------------------------------------------------------------------
    # スタティックルーティング
    # ------------------------------------------------------------------
    def add_static_route(self, destination: str, mask: str, next_hop: str) -> None:
        if not (_validate_ipv4(destination) and _validate_ipv4(mask) and _validate_ipv4(next_hop)):
            raise ValueError("invalid static route parameters")
        network = IPv4Network(f"{destination}/{mask}", strict=False)
        route = StaticRoute(network=network, next_hop=IPv4Address(next_hop))
        if route in self.static_routes:
            raise ValueError("static route already exists")
        self.static_routes.add(route)
        entry = (network.network_address.exploded, network.netmask.exploded, IPv4Address(next_hop).exploded)
        if entry not in self.static_route_entries:
            self.static_route_entries.append(entry)
        self._log(f"Static route {network} via {next_hop} added")

    def remove_static_route(self, destination: str, mask: str, next_hop: str) -> None:
        if not (_validate_ipv4(destination) and _validate_ipv4(mask) and _validate_ipv4(next_hop)):
            raise ValueError("invalid static route parameters")
        network = IPv4Network(f"{destination}/{mask}", strict=False)
        route = StaticRoute(network=network, next_hop=IPv4Address(next_hop))
        if route not in self.static_routes:
            raise ValueError("static route not found")
        self.static_routes.remove(route)
        entry = (network.network_address.exploded, network.netmask.exploded, IPv4Address(next_hop).exploded)
        if entry in self.static_route_entries:
            self.static_route_entries.remove(entry)
        self._log(f"Static route {network} via {next_hop} removed")

    # ------------------------------------------------------------------
    # RIP
    # ------------------------------------------------------------------
    def enable_rip(self) -> None:
        self.rip_enabled = True
        self._log("RIP enabled")

    def disable_rip(self) -> None:
        self.rip_enabled = False
        self._log("RIP disabled")
        self.rip_networks.clear()

    def set_rip_version(self, version: int) -> None:
        if version not in {1, 2}:
            raise ValueError("RIP version must be 1 or 2")
        self.rip_version = version
        self._log(f"RIP version set to {version}")

    def add_rip_network(self, network: str) -> None:
        if not _validate_ipv4(network):
            raise ValueError("invalid RIP network address")
        prefix = IPv4Network(f"{network}/24", strict=False)
        self.rip_networks.add(prefix)
        self._log(f"RIP network {prefix} added")

    def remove_rip_network(self, network: str) -> None:
        if not _validate_ipv4(network):
            raise ValueError("invalid RIP network address")
        prefix = IPv4Network(f"{network}/24", strict=False)
        if prefix in self.rip_networks:
            self.rip_networks.remove(prefix)
            self._log(f"RIP network {prefix} removed")
        else:
            raise ValueError("RIP network not found")

    def set_rip_auto_summary(self, enabled: bool) -> None:
        self.rip_auto_summary = enabled
        state = "enabled" if enabled else "disabled"
        self._log(f"RIP auto-summary {state}")

    def set_rip_redistribute_static(self, enabled: bool) -> None:
        self.rip_redistribute_static = enabled
        state = "enabled" if enabled else "disabled"
        self._log(f"RIP redistribute static {state}")

    # ------------------------------------------------------------------
    # OSPF
    # ------------------------------------------------------------------
    def enable_ospf(self, process_id: int) -> None:
        if process_id <= 0:
            raise ValueError("process-id must be positive")
        self.ospf_enabled = True
        self.ospf_process_id = process_id
        if not self.ospf_router_id:
            for iface in self._interfaces.values():
                if iface.ip_address and _validate_ipv4(iface.ip_address):
                    self.ospf_router_id = IPv4Address(iface.ip_address)
                    break
            if not self.ospf_router_id:
                self.ospf_router_id = IPv4Address("1.1.1.1")
        self._log(f"OSPF process {process_id} enabled with router-id {self.ospf_router_id}")

    def disable_ospf(self) -> None:
        self.ospf_enabled = False
        self.ospf_process_id = None
        self.ospf_networks.clear()
        self._log("OSPF disabled")

    def set_ospf_router_id(self, router_id: str) -> None:
        if not _validate_ipv4(router_id):
            raise ValueError("invalid router-id")
        self.ospf_router_id = IPv4Address(router_id)
        self._log(f"OSPF router-id set to {router_id}")

    def add_ospf_network(self, ip: str, wildcard: str, area: str) -> None:
        if not (_validate_ipv4(ip) and _validate_ipv4(wildcard)):
            raise ValueError("invalid IP or wildcard")
        network = IPv4Interface(f"{ip}/{wildcard}").network
        entry = OspfNetwork(network=network, area=int(area))
        self.ospf_networks.add(entry)
        self._log(f"OSPF network {network} area {area} added")

    def remove_ospf_network(self, ip: str, wildcard: str, area: str) -> None:
        if not (_validate_ipv4(ip) and _validate_ipv4(wildcard)):
            raise ValueError("invalid IP or wildcard")
        network = IPv4Interface(f"{ip}/{wildcard}").network
        entry = OspfNetwork(network=network, area=int(area))
        if entry in self.ospf_networks:
            self.ospf_networks.remove(entry)
            self._log(f"OSPF network {network} area {area} removed")
        else:
            raise ValueError("OSPF network not found")

    def set_ospf_redistribute_static(self, enabled: bool) -> None:
        self.ospf_redistribute_static = enabled
        state = "enabled" if enabled else "disabled"
        self._log(f"OSPF redistribute static {state}")

    def show_ip_ospf_neighbor(self) -> str:
        if not self.ospf_enabled:
            return "%OSPF is not enabled"
        lines = [
            "Neighbor ID     Pri   State           Dead Time   Address         Interface",
            f"{self.ospf_router_id or '1.1.1.1':<15}  1     FULL/DR        00:00:33    192.168.1.1     GigabitEthernet0/0",
        ]
        return "\n".join(lines)

    def show_ip_ospf_database(self) -> str:
        if not self.ospf_enabled:
            return "%OSPF is not enabled"
        lines = [
            "            OSPF Router with ID (1.1.1.1) (Process ID 1)",
            "",
            "                Router Link States (Area 0)",
            "Link ID         ADV Router      Age         Seq#       Checksum Link count",
            "1.1.1.1         1.1.1.1         600         80000001   0x009F   1",
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # BGP
    # ------------------------------------------------------------------
    def enable_bgp(self, asn: int) -> None:
        if asn <= 0:
            raise ValueError("AS number must be positive")
        self.bgp_enabled = True
        self.bgp_asn = asn
        self._log(f"BGP enabled with AS {asn}")

    def disable_bgp(self) -> None:
        self.bgp_enabled = False
        self.bgp_asn = None
        self.bgp_neighbors.clear()
        self.bgp_networks.clear()
        self._log("BGP disabled")

    def add_bgp_neighbor(self, neighbor: str, remote_as: str) -> None:
        if not (_validate_ipv4(neighbor) and remote_as.isdigit()):
            raise ValueError("invalid neighbor or remote-as")
        address = IPv4Address(neighbor)
        neighbor_entry = BgpNeighbor(address=address, remote_as=int(remote_as))
        self.bgp_neighbors[address] = neighbor_entry
        self._log(f"BGP neighbor {neighbor} remote-as {remote_as} added")

    def remove_bgp_neighbor(self, neighbor: str) -> None:
        if not _validate_ipv4(neighbor):
            raise ValueError("invalid neighbor address")
        address = IPv4Address(neighbor)
        if address in self.bgp_neighbors:
            del self.bgp_neighbors[address]
            self._log(f"BGP neighbor {neighbor} removed")
        else:
            raise ValueError("BGP neighbor not found")

    def add_bgp_network(self, network: str, mask: str) -> None:
        if not (_validate_ipv4(network) and _validate_ipv4(mask)):
            raise ValueError("invalid network or mask")
        prefix = IPv4Network(f"{network}/{mask}", strict=False)
        entry = BgpNetwork(prefix=prefix)
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

    def show_version(self) -> str:
        """Return basic version and system information."""

        hostname = getattr(self, "name", "Router")
        return (
            f"\n{hostname} Simulator IOS Software, Version 15.2(4)M\n"
            f"Compiled by Codex, {__name__}\n"
            "System image file is 'flash:cisco_router_sim.bin'\n"
            "Router uptime is simulated\n"
        )

    def show_running_config(self) -> str:
        """Return a simplified running configuration for the router."""

        lines: list[str] = []
        lines.append(f"hostname {self.name}")
        lines.append("!")
        lines.append("interface configurations:")
        for if_name in sorted(self._interfaces):
            iface = self._interfaces[if_name]
            lines.append(f" interface {if_name}")
            if iface.ip_address and iface.subnet_mask:
                lines.append(f"  ip address {iface.ip_address} {iface.subnet_mask}")
            else:
                lines.append("  no ip address")
            lines.append("  no shutdown" if iface.admin_up else "  shutdown")
            lines.append("!")
        if self.static_routes:
            lines.append("ip route entries:")
            for route in sorted(
                self.static_routes,
                key=lambda r: (
                    int(r.network.network_address),
                    r.network.prefixlen,
                    int(r.next_hop),
                ),
            ):
                network_addr = route.network.network_address.exploded
                netmask = route.network.netmask.exploded
                next_hop = route.next_hop.exploded
                lines.append(f" ip route {network_addr} {netmask} {next_hop}")
        lines.append("end")
        return "\n".join(lines)

    def show_ip_route(self) -> str:
        """Display the routing table, including static routes."""

        lines = [
            "Codes: C - connected, S - static, R - RIP, O - OSPF, B - BGP",
            "",
            "Gateway of last resort is not set",
            "",
        ]
        if not self.static_route_entries:
            lines.append("<no static routes>")
            return "\n".join(lines)

        for network, mask, next_hop in self.static_route_entries:
            lines.append(f"S    {network} {mask} [1/0] via {next_hop}")
        return "\n".join(lines)

    def show_ip_interface_brief(self) -> str:
        """Display a summary of all router interfaces and their IP status (Cisco IOS style)."""

        lines = [
            "Interface              IP-Address      OK? Method Status                Protocol"
        ]
        for if_name in sorted(self._interfaces):
            iface = self._interfaces[if_name]
            ip_addr = iface.ip_address or "unassigned"
            status = "up" if iface.admin_up else "administratively down"
            protocol = "up" if iface.admin_up else "down"
            lines.append(
                f"{if_name:<22}{ip_addr:<15}YES manual {status:<20}{protocol}"
            )
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
