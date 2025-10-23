"""Command handler for Cisco router simulator CLI — EXEC modes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from router_sim.cli.parser import match_command

__all__ = ["handle_user_exec", "handle_priv_exec"]

if TYPE_CHECKING:
    from router_sim.cli.dispatcher import RouterCLI


def handle_user_exec(cli: "RouterCLI", command: str) -> str:
    if match_command(command, "enable") is not None:
        cli._mode = "priv_exec"
        return ""
    match = match_command(command, "ping", allow_suffix=True)
    if match is not None:
        remainder_tokens, remainder_text = match
        tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
        if len(tokens) != 1:
            return "Usage: ping <ip-address>"
        return cli.router.ping(tokens[0])
    match = match_command(command, "traceroute", allow_suffix=True)
    if match is not None:
        remainder_tokens, remainder_text = match
        tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
        if len(tokens) != 1:
            return "Usage: traceroute <ip-address>"
        return cli.router.traceroute(tokens[0])
    if match_command(command, "exit") is not None:
        return "Session closed."
    if match_command(command, "logout") is not None:
        return "Session closed."
    shared = cli._handle_show(command)
    if shared is not None:
        return shared
    return "% Command available in privileged EXEC mode."


def handle_priv_exec(cli: "RouterCLI", command: str) -> str:
    if match_command(command, "disable") is not None:
        cli._mode = "user_exec"
        return ""
    if match_command(command, "configure terminal") is not None:
        cli._mode = "config"
        return "Enter configuration commands, one per line. End with CNTL/Z."
    match = match_command(command, "ping", allow_suffix=True)
    if match is not None:
        remainder_tokens, remainder_text = match
        tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
        if len(tokens) != 1:
            return "Usage: ping <ip-address>"
        return cli.router.ping(tokens[0])
    match = match_command(command, "traceroute", allow_suffix=True)
    if match is not None:
        remainder_tokens, remainder_text = match
        tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
        if len(tokens) != 1:
            return "Usage: traceroute <ip-address>"
        return cli.router.traceroute(tokens[0])
    if match_command(command, "exit") is not None:
        cli._mode = "user_exec"
        return ""
    if match_command(command, "logout") is not None:
        cli._mode = "user_exec"
        return ""
    if match_command(command, "show startup-config") is not None:
        return cli.router.show_startup_config()
    if match_command(command, "show processes") is not None:
        return cli.router.show_processes()
    if match_command(command, "show users") is not None:
        return cli.router.show_users()
    if match_command(command, "show ip route") is not None:
        return cli.router.show_ip_route()
    if match_command(command, "show ip ospf neighbor") is not None:
        return cli.router.show_ip_ospf_neighbor()
    if match_command(command, "show ip ospf database") is not None:
        return cli.router.show_ip_ospf_database()
    if match_command(command, "show ip bgp") is not None:
        return cli.router.show_ip_bgp()
    if match_command(command, "show running-config") is not None:
        return cli.router.show_running_config()
    shared = cli._handle_show(command)
    if shared is not None:
        return shared
    if match_command(command, "copy running-config startup-config", allow_suffix=True) is not None:
        cli.router.save_startup_config()
        return "Building configuration...\n[OK]"
    if match_command(command, "copy run start", allow_suffix=True) is not None:
        cli.router.save_startup_config()
        return "Building configuration...\n[OK]"
    if match_command(command, "write memory", allow_suffix=True) is not None:
        cli.router.save_startup_config()
        return "Building configuration...\n[OK]"
    if match_command(command, "ip route", allow_suffix=True) is not None:
        _, remainder = match_command(command, "ip route", allow_suffix=True)
        tokens = remainder.split() if remainder else []
        if len(tokens) == 3:
            network, mask, next_hop = tokens
            try:
                cli.router.add_static_route(network, mask, next_hop)
                return f"Static route {network}/{mask} via {next_hop} added"
            except Exception as exc:  # pragma: no cover - defensive
                return f"% {exc}"
        return "% Usage: ip route <network> <mask> <next-hop>"
    if match_command(command, "reload") is not None:
        message = cli.router.reload()
        cli._mode = "user_exec"
        return message
    if match_command(command, "clear arp-cache") is not None:
        cli.router.clear_arp_cache()
        return "ARP cache cleared"
    return f"% Unknown command: {command}"
