"""Command handler for Cisco router simulator CLI — configuration modes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from router_sim.cli.parser import match_command

__all__ = ["handle_config", "handle_interface"]

if TYPE_CHECKING:
    from router_sim.cli.dispatcher import RouterCLI


def handle_config(cli: "RouterCLI", command: str) -> str:
    if match_command(command, "exit") is not None:
        cli._mode = "priv_exec"
        return ""
    if match_command(command, "end") is not None:
        cli._mode = "priv_exec"
        return ""
    match = match_command(command, "hostname", allow_suffix=True)
    if match is not None:
        _, remainder = match
        if not remainder:
            return "Usage: hostname <name>"
        try:
            cli.router.set_hostname(remainder)
        except ValueError as exc:
            return f"% {exc}"
        return ""
    match = match_command(command, "enable secret", allow_suffix=True)
    if match is not None:
        _, remainder = match
        if not remainder:
            return "Usage: enable secret <password>"
        try:
            cli.router.set_enable_secret(remainder)
        except ValueError as exc:
            return f"% {exc}"
        return ""
    if match_command(command, "service password-encryption") is not None:
        cli.router.set_password_encryption(True)
        return ""
    if match_command(command, "no service password-encryption") is not None:
        cli.router.set_password_encryption(False)
        return ""
    if match_command(command, "no ip domain-lookup") is not None:
        cli.router.set_domain_lookup(False)
        return ""
    if match_command(command, "ip domain-lookup") is not None:
        cli.router.set_domain_lookup(True)
        return ""
    match = match_command(command, "ip name-server", allow_suffix=True)
    if match is not None:
        remainder_tokens, remainder_text = match
        tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
        if not tokens:
            return "Usage: ip name-server <address> [address ...]"
        try:
            cli.router.set_name_servers(tokens)
        except ValueError as exc:
            return f"% {exc}"
        return ""
    match = match_command(command, "no ip name-server", allow_suffix=True)
    if match is not None:
        remainder_tokens, remainder_text = match
        tokens = remainder_tokens if remainder_tokens else (
            remainder_text.split() if remainder_text else []
        )
        try:
            cli.router.remove_name_servers(tokens if tokens else None)
        except ValueError as exc:
            return f"% {exc}"
        return ""
    match = match_command(command, "banner motd", allow_suffix=True)
    if match is not None:
        _, remainder = match
        if not remainder:
            return "Usage: banner motd #text#"
        message = cli._parse_banner(remainder)
        if message is None:
            return "Usage: banner motd #text#"
        cli.router.set_banner_motd(message)
        return ""
    if match_command(command, "no banner motd") is not None:
        cli.router.set_banner_motd(None)
        return ""
    match = match_command(command, "clock timezone", allow_suffix=True)
    if match is not None:
        remainder_tokens, _ = match
        if len(remainder_tokens) != 2:
            return "Usage: clock timezone <zone> <offset>"
        zone, offset_str = remainder_tokens
        try:
            offset = int(offset_str)
        except ValueError:
            return "% Offset must be numeric"
        cli.router.set_clock_timezone(zone, offset)
        return ""
    if match_command(command, "router rip") is not None:
        cli.router.enable_rip()
        cli._mode = "router_rip"
        cli._current_router_process = "rip"
        return "Enter RIP configuration commands. End with CNTL/Z."
    if match_command(command, "no router rip") is not None:
        cli.router.disable_rip()
        cli._current_router_process = None
        return ""
    match = match_command(command, "router ospf", allow_suffix=True)
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
            cli.router.enable_ospf(process_id)
        except ValueError as exc:
            return f"% {exc}"
        cli._mode = "router_ospf"
        cli._current_router_process = "ospf"
        return "Enter OSPF configuration commands. End with CNTL/Z."
    if match_command(command, "no router ospf") is not None:
        cli.router.disable_ospf()
        cli._current_router_process = None
        return ""
    match = match_command(command, "router bgp", allow_suffix=True)
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
            cli.router.enable_bgp(asn)
        except ValueError as exc:
            return f"% {exc}"
        cli._mode = "router_bgp"
        cli._current_router_process = "bgp"
        return "Enter BGP configuration commands. End with CNTL/Z."
    if match_command(command, "no router bgp", allow_suffix=True) is not None:
        cli.router.disable_bgp()
        if cli._mode == "config":
            cli._current_router_process = None
            return ""
    match = match_command(command, "vlan", allow_suffix=True)
    if match is not None:
        remainder_tokens, _ = match
        if len(remainder_tokens) != 1:
            return "Usage: vlan <id>"
        try:
            vlan = int(remainder_tokens[0])
        except ValueError:
            return "% VLAN must be numeric"
        try:
            cli.router.create_vlan(vlan)
        except ValueError as exc:
            return f"% {exc}"
        return ""
    match = match_command(command, "no vlan", allow_suffix=True)
    if match is not None:
        remainder_tokens, _ = match
        if len(remainder_tokens) != 1:
            return "Usage: no vlan <id>"
        try:
            vlan = int(remainder_tokens[0])
        except ValueError:
            return "% VLAN must be numeric"
        try:
            cli.router.delete_vlan(vlan)
        except ValueError as exc:
            return f"% {exc}"
        return ""
    match = match_command(command, "ip route", allow_suffix=True)
    if match is not None:
        remainder_tokens, _ = match
        if len(remainder_tokens) != 3:
            return "Usage: ip route <destination> <mask> <next-hop>"
        destination, mask, next_hop = remainder_tokens
        try:
            cli.router.add_static_route(destination, mask, next_hop)
        except ValueError as exc:
            return f"% {exc}"
        return ""
    match = match_command(command, "no ip route", allow_suffix=True)
    if match is not None:
        remainder_tokens, _ = match
        if len(remainder_tokens) != 3:
            return "Usage: no ip route <destination> <mask> <next-hop>"
        destination, mask, next_hop = remainder_tokens
        try:
            cli.router.remove_static_route(destination, mask, next_hop)
        except ValueError as exc:
            return f"% {exc}"
        return ""
    match = match_command(command, "ip nat pool", allow_suffix=True)
    if match is not None:
        remainder_tokens, remainder_text = match
        tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
        if len(tokens) != 5 or tokens[3].lower() != "netmask":
            return "Usage: ip nat pool <name> <start-ip> <end-ip> netmask <mask>"
        name, start, end, _, mask = tokens
        try:
            cli.router.add_nat_pool(name, start, end, mask)
        except ValueError as exc:
            return f"% {exc}"
        return ""
    match = match_command(command, "no ip nat pool", allow_suffix=True)
    if match is not None:
        remainder_tokens, remainder_text = match
        tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
        if len(tokens) != 1:
            return "Usage: no ip nat pool <name>"
        try:
            cli.router.remove_nat_pool(tokens[0])
        except ValueError as exc:
            return f"% {exc}"
        return ""
    match = match_command(command, "ip nat inside source list", allow_suffix=True)
    if match is not None:
        remainder_tokens, remainder_text = match
        tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
        if len(tokens) not in {3, 4} or tokens[1].lower() != "pool":
            return "Usage: ip nat inside source list <list> pool <name> [overload]"
        access_list = tokens[0]
        pool = tokens[2]
        overload = len(tokens) == 4 and tokens[3].lower() == "overload"
        try:
            cli.router.add_nat_mapping(access_list, pool, overload)
        except ValueError as exc:
            return f"% {exc}"
        return ""
    match = match_command(command, "no ip nat inside source list", allow_suffix=True)
    if match is not None:
        remainder_tokens, remainder_text = match
        tokens = remainder_tokens if remainder_tokens else (remainder_text.split() if remainder_text else [])
        if len(tokens) != 3 or tokens[1].lower() != "pool":
            return "Usage: no ip nat inside source list <list> pool <name>"
        access_list = tokens[0]
        pool = tokens[2]
        try:
            cli.router.remove_nat_mapping(access_list, pool)
        except ValueError as exc:
            return f"% {exc}"
        return ""
    if match_command(command, "service timestamps log datetime") is not None:
        cli.router.set_service_timestamps(True)
        return ""
    if match_command(command, "no service timestamps log datetime") is not None:
        cli.router.set_service_timestamps(False)
        return ""
    match = match_command(command, "interface", allow_suffix=True)
    if match is not None:
        remainder_tokens, remainder_text = match
        if not remainder_tokens and not remainder_text:
            return "Usage: interface <name>"
        candidate = remainder_text or remainder_tokens[0]
        resolved = cli._resolve_interface_name(candidate)
        if resolved is None:
            return f"% unknown interface: {candidate}"
        cli._current_interface = resolved
        cli._mode = "interface"
        return f"Enter configuration commands for {resolved}. End with CNTL/Z."
    return f"% Unknown configuration command: {command}"


def handle_interface(cli: "RouterCLI", command: str) -> str:
    if match_command(command, "exit") is not None:
        cli._mode = "config"
        cli._current_interface = None
        return ""
    if match_command(command, "end") is not None:
        cli._mode = "priv_exec"
        cli._current_interface = None
        return ""
    if not cli._current_interface:
        return "% No interface selected"
    iface = cli._current_interface
    if match_command(command, "shutdown") is not None:
        cli.router.set_interface_admin_state(iface, False)
        return ""
    if match_command(command, "no shutdown") is not None:
        cli.router.set_interface_admin_state(iface, True)
        return ""
    if match_command(command, "ip nat inside") is not None:
        cli.router.set_interface_nat_role(iface, "inside")
        return ""
    if match_command(command, "ip nat outside") is not None:
        cli.router.set_interface_nat_role(iface, "outside")
        return ""
    if match_command(command, "no ip nat inside") is not None:
        cli.router.clear_interface_nat_role(iface, "inside")
        return ""
    if match_command(command, "no ip nat outside") is not None:
        cli.router.clear_interface_nat_role(iface, "outside")
        return ""
    match = match_command(command, "ip address", allow_suffix=True)
    if match is not None:
        remainder_tokens, _ = match
        if len(remainder_tokens) != 2:
            return "Usage: ip address <address> <mask>"
        ip, mask = remainder_tokens
        try:
            cli.router.set_interface_ip(iface, ip, mask)
        except ValueError as exc:
            return f"% {exc}"
        return ""
    if match_command(command, "no ip address") is not None:
        cli.router.clear_interface_ip(iface)
        return ""
    match = match_command(command, "description", allow_suffix=True)
    if match is not None:
        _, remainder = match
        cli.router.set_interface_description(iface, remainder)
        return ""
    return f"% Unknown interface command: {command}"
