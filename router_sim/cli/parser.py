"""Command handler for Cisco router simulator CLI — parsing helpers."""

from __future__ import annotations

from typing import Optional

from router_sim.router_core import CiscoRouter

__all__ = [
    "split_interface_token",
    "match_command",
    "is_placeholder",
    "placeholder_values",
]


def split_interface_token(name: str) -> tuple[str, str]:
    for index, char in enumerate(name):
        if char.isdigit():
            return name[:index], name[index:]
    return name, ""


def match_command(
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


def is_placeholder(token: str) -> bool:
    return token.startswith("<") and token.endswith(">")


def placeholder_values(router: CiscoRouter, placeholder: str) -> list[str]:
    if placeholder == "<interface>":
        return sorted(router._interfaces.keys())
    if placeholder == "<ip>":
        suggestions = [ns.exploded for ns in router.name_servers]
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
        vlans = sorted(router.vlans) or ["10"]
        return [str(v) for v in vlans]
    if placeholder == "<next-hop>":
        return ["192.168.1.1"]
    if placeholder == "<version>":
        return ["1", "2"]
    if placeholder == "<network>":
        networks = [n.network_address.exploded for n in router.rip_networks]
        return networks or ["192.168.1.0"]
    if placeholder == "<process>":
        return [str(router.ospf_process_id or 1)]
    if placeholder == "<wildcard>":
        return ["0.0.0.255"]
    if placeholder == "<area>":
        areas = {n.area for n in router.ospf_networks}
        return [str(area) for area in sorted(areas)] or ["0"]
    if placeholder == "<asn>":
        return [str(router.bgp_asn or 65000)]
    if placeholder == "<neighbor>":
        return [addr.exploded for addr in router.bgp_neighbors] or ["192.0.2.1"]
    if placeholder == "<remote-as>":
        return [str(neighbor.remote_as) for neighbor in router.bgp_neighbors.values()] or ["65001"]
    if placeholder == "<nat_pool>":
        return sorted(router.nat_pools.keys()) or ["POOL1"]
    if placeholder == "<acl>":
        lists = {mapping.access_list for mapping in router.nat_mappings}
        return [acl for acl in sorted(lists)] or ["1"]
    return []
