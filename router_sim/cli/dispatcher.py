"""Command handler for Cisco router simulator CLI — dispatcher and state management."""

from __future__ import annotations

from typing import Optional

from router_sim.router_core import CiscoRouter

from router_sim.cli.config_commands import handle_config, handle_interface
from router_sim.cli.exec_commands import handle_priv_exec, handle_user_exec
from router_sim.cli.parser import (
    is_placeholder,
    match_command,
    placeholder_values,
    split_interface_token,
)
from router_sim.cli.router_commands import handle_router_bgp, handle_router_ospf, handle_router_rip

__all__ = ["RouterCLI"]


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

        alias_prefix, alias_suffix = split_interface_token(alias)
        if not alias_prefix:
            return None
        candidates: list[str] = []
        for name in interfaces:
            prefix, suffix = split_interface_token(name)
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
            ["ip", "name-server", "<ip>"],
            ["no", "ip", "name-server", "<ip>"],
            ["ip", "domain-lookup"],
            ["no", "ip", "domain-lookup"],
            ["banner", "motd", "<banner>"],
            ["no", "banner", "motd"],
            ["clock", "timezone", "<zone>", "<offset>"],
            ["router", "rip"],
            ["no", "router", "rip"],
            ["router", "ospf", "<process>"],
            ["no", "router", "ospf"],
            ["router", "bgp", "<asn>"],
            ["no", "router", "bgp"],
            ["ip", "route", "<ip>", "<mask>", "<next-hop>"],
            ["no", "ip", "route", "<ip>", "<mask>", "<next-hop>"],
            ["vlan", "<vlan>"],
            ["no", "vlan", "<vlan>"],
            ["ip", "nat", "pool", "<nat_pool>", "<ip>", "<ip>", "netmask", "<mask>"],
            ["no", "ip", "nat", "pool", "<nat_pool>"],
            ["ip", "nat", "inside", "source", "list", "<acl>", "pool", "<nat_pool>", "overload"],
            ["ip", "nat", "inside", "source", "list", "<acl>", "pool", "<nat_pool>"],
            ["no", "ip", "nat", "inside", "source", "list", "<acl>", "pool", "<nat_pool>"],
            ["service", "timestamps", "log", "datetime"],
            ["no", "service", "timestamps", "log", "datetime"],
        ]

    def _interface_commands(self) -> list[list[str]]:
        return [
            ["exit"],
            ["end"],
            ["help"],
            ["description", "<text>"],
            ["shutdown"],
            ["no", "shutdown"],
            ["ip", "address", "<ip>", "<mask>"],
            ["no", "ip", "address"],
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
            ["no", "auto-summary"],
            ["auto-summary"],
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
                if is_placeholder(tmpl):
                    continue
                if not tmpl.startswith(token.lower()):
                    valid = False
                    break
            if not valid:
                continue
            if len(template) <= len(prefix_tokens):
                continue
            candidate = template[len(prefix_tokens)]
            values = placeholder_values(self.router, candidate) if is_placeholder(candidate) else [candidate]
            for value in values:
                if value.lower().startswith(fragment_lower):
                    matches.add(value)
        return sorted(matches)

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
            return handle_user_exec(self, command)
        if self._mode == "priv_exec":
            return handle_priv_exec(self, command)
        if self._mode == "config":
            return handle_config(self, command)
        if self._mode == "interface":
            return handle_interface(self, command)
        if self._mode == "router_rip":
            return handle_router_rip(self, command)
        if self._mode == "router_ospf":
            return handle_router_ospf(self, command)
        if self._mode == "router_bgp":
            return handle_router_bgp(self, command)
        raise RuntimeError(f"invalid CLI mode: {self._mode}")

    def _handle_show(self, command: str) -> Optional[str]:
        if match_command(command, "show arp") is not None:
            return self.router.show_arp()
        if match_command(command, "show interfaces") is not None:
            return self.router.show_interfaces()
        if match_command(command, "show ip interface brief") is not None:
            return self.router.show_ip_interface_brief()
        if match_command(command, "show ip ospf neighbor") is not None:
            return self.router.show_ip_ospf_neighbor()
        if match_command(command, "show ip ospf database") is not None:
            return self.router.show_ip_ospf_database()
        if match_command(command, "show ip bgp") is not None:
            return self.router.show_ip_bgp()
        if match_command(command, "show ip nat translations") is not None:
            return self.router.show_ip_nat_translations()
        if match_command(command, "show ip protocols") is not None:
            return self.router.show_ip_protocols()
        if match_command(command, "show ip route") is not None:
            return self.router.show_ip_route()
        if match_command(command, "show version") is not None:
            return self.router.show_version()
        return None

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
