"""Command handler for Cisco router simulator CLI — routing process modes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from router_sim.cli.parser import match_command

__all__ = ["handle_router_rip", "handle_router_ospf", "handle_router_bgp"]

if TYPE_CHECKING:
    from router_sim.cli.dispatcher import RouterCLI


def handle_router_rip(cli: "RouterCLI", command: str) -> str:
    if match_command(command, "exit") is not None:
        cli._mode = "config"
        cli._current_router_process = None
        return ""
    if match_command(command, "end") is not None:
        cli._mode = "priv_exec"
        cli._current_router_process = None
        return ""
    if match_command(command, "no router rip") is not None:
        cli.router.disable_rip()
        cli._mode = "config"
        cli._current_router_process = None
        return ""
    if not cli.router.rip_enabled:
        return "% RIP is not enabled"
    match = match_command(command, "version", allow_suffix=True)
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
            cli.router.set_rip_version(version)
        except ValueError as exc:
            return f"% {exc}"
        return ""
    match = match_command(command, "network", allow_suffix=True)
    if match is not None:
        remainder_tokens, remainder_text = match
        tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
        if len(tokens) != 1:
            return "Usage: network <address>"
        try:
            cli.router.add_rip_network(tokens[0])
        except ValueError as exc:
            return f"% {exc}"
        return ""
    match = match_command(command, "no network", allow_suffix=True)
    if match is not None:
        remainder_tokens, remainder_text = match
        tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
        if len(tokens) != 1:
            return "Usage: no network <address>"
        try:
            cli.router.remove_rip_network(tokens[0])
        except ValueError as exc:
            return f"% {exc}"
        return ""
    if match_command(command, "no auto-summary") is not None:
        cli.router.set_rip_auto_summary(False)
        return ""
    if match_command(command, "auto-summary") is not None:
        cli.router.set_rip_auto_summary(True)
        return ""
    if match_command(command, "redistribute static") is not None:
        cli.router.set_rip_redistribute_static(True)
        return ""
    if match_command(command, "no redistribute static") is not None:
        cli.router.set_rip_redistribute_static(False)
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


def handle_router_ospf(cli: "RouterCLI", command: str) -> str:
    if match_command(command, "exit") is not None:
        cli._mode = "config"
        cli._current_router_process = None
        return ""
    if match_command(command, "end") is not None:
        cli._mode = "priv_exec"
        cli._current_router_process = None
        return ""
    if match_command(command, "no router ospf") is not None:
        cli.router.disable_ospf()
        cli._mode = "config"
        cli._current_router_process = None
        return ""
    if not cli.router.ospf_enabled:
        return "% OSPF is not enabled"
    match = match_command(command, "router-id", allow_suffix=True)
    if match is not None:
        remainder_tokens, remainder_text = match
        tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
        if len(tokens) != 1:
            return "Usage: router-id <ip>"
        try:
            cli.router.set_ospf_router_id(tokens[0])
        except ValueError as exc:
            return f"% {exc}"
        return ""
    match = match_command(command, "network", allow_suffix=True)
    if match is not None:
        remainder_tokens, remainder_text = match
        tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
        if len(tokens) != 4 or tokens[2].lower() != "area":
            return "Usage: network <ip> <wildcard> area <id>"
        ip_addr, wildcard, _, area = tokens
        try:
            cli.router.add_ospf_network(ip_addr, wildcard, area)
        except ValueError as exc:
            return f"% {exc}"
        return ""
    match = match_command(command, "no network", allow_suffix=True)
    if match is not None:
        remainder_tokens, remainder_text = match
        tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
        if len(tokens) != 4 or tokens[2].lower() != "area":
            return "Usage: no network <ip> <wildcard> area <id>"
        ip_addr, wildcard, _, area = tokens
        try:
            cli.router.remove_ospf_network(ip_addr, wildcard, area)
        except ValueError as exc:
            return f"% {exc}"
        return ""
    if match_command(command, "redistribute static") is not None:
        cli.router.set_ospf_redistribute_static(True)
        return ""
    if match_command(command, "no redistribute static") is not None:
        cli.router.set_ospf_redistribute_static(False)
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


def handle_router_bgp(cli: "RouterCLI", command: str) -> str:
    if match_command(command, "exit") is not None:
        cli._mode = "config"
        cli._current_router_process = None
        return ""
    if match_command(command, "end") is not None:
        cli._mode = "priv_exec"
        cli._current_router_process = None
        return ""
    if match_command(command, "no router bgp") is not None:
        cli.router.disable_bgp()
        cli._mode = "config"
        cli._current_router_process = None
        return ""
    if not cli.router.bgp_enabled:
        return "% BGP is not enabled"
    match = match_command(command, "neighbor", allow_suffix=True)
    if match is not None:
        remainder_tokens, remainder_text = match
        tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
        if len(tokens) != 3 or tokens[1].lower() != "remote-as":
            return "Usage: neighbor <ip> remote-as <asn>"
        ip_addr, _, remote_as = tokens
        try:
            cli.router.add_bgp_neighbor(ip_addr, remote_as)
        except ValueError as exc:
            return f"% {exc}"
        return ""
    match = match_command(command, "no neighbor", allow_suffix=True)
    if match is not None:
        remainder_tokens, remainder_text = match
        tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
        if len(tokens) != 1:
            return "Usage: no neighbor <ip>"
        try:
            cli.router.remove_bgp_neighbor(tokens[0])
        except ValueError as exc:
            return f"% {exc}"
        return ""
    match = match_command(command, "network", allow_suffix=True)
    if match is not None:
        remainder_tokens, remainder_text = match
        tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
        if len(tokens) != 3 or tokens[1].lower() != "mask":
            return "Usage: network <ip> mask <mask>"
        ip, _, mask = tokens
        try:
            cli.router.add_bgp_network(ip, mask)
        except ValueError as exc:
            return f"% {exc}"
        return ""
    match = match_command(command, "no network", allow_suffix=True)
    if match is not None:
        remainder_tokens, remainder_text = match
        tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
        if len(tokens) != 3 or tokens[1].lower() != "mask":
            return "Usage: no network <ip> mask <mask>"
        ip, _, mask = tokens
        try:
            cli.router.remove_bgp_network(ip, mask)
        except ValueError as exc:
            return f"% {exc}"
        return ""
    if match_command(command, "redistribute static") is not None:
        cli.router.set_bgp_redistribute_static(True)
        return ""
    if match_command(command, "no redistribute static") is not None:
        cli.router.set_bgp_redistribute_static(False)
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
