"""Command-line interpreter and mode handling for the educational Ethernet switch simulator."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Optional

try:  # pragma: no cover - 環境依存
    import readline
except ImportError:  # pragma: no cover - Windows 想定
    readline = None

from switch_sim.switch_core import EthernetSwitch, Frame
from switch_sim.utils import validate_ipv4_address


class SwitchCLI:
    """:class:`EthernetSwitch` 用の小さなコマンドラインインタプリタです。"""

    def __init__(self, switch: EthernetSwitch) -> None:
        self.switch = switch
        self._mode = "user_exec"  # 状態: user_exec | priv_exec | config | interface | interface_svi | vlan | line_console | line_vty
        self._current_interface: Optional[str] = None
        self._current_interfaces: list[str] = []
        self._current_vlan: Optional[int] = None
        self._history: list[str] = []
        self._completion_matches: list[str] = []
        self._current_svi: Optional[int] = None
        self._current_line: Optional[str] = None
        self._current_line_range: Optional[tuple[int, int]] = None

    @staticmethod
    def _split_port_token(name: str) -> tuple[str, str]:
        """ポート名を英字部分と残りの部分に分割します。"""

        for index, char in enumerate(name):
            if not char.isalpha():
                return name[:index], name[index:]
        return name, ""

    def _match_command(
        self,
        command: str,
        canonical: str,
        allow_suffix: bool = False,
    ) -> Optional[tuple[list[str], str]]:
        """短縮入力を含むコマンドを正規コマンドと照合します。"""

        tokens = command.split()
        canonical_tokens = canonical.lower().split()
        if len(tokens) < len(canonical_tokens):
            return None
        for index, expected in enumerate(canonical_tokens):
            candidate = tokens[index].lower()
            if len(candidate) > len(expected):
                return None
            if not expected.startswith(candidate):
                return None
        remainder_tokens = tokens[len(canonical_tokens) :]
        if remainder_tokens and not allow_suffix:
            return None
        remainder_text = " ".join(remainder_tokens)
        return remainder_tokens, remainder_text

    def _resolve_interface_name(self, alias: str) -> Optional[str]:
        """短縮表記を含むインターフェース名を正式名称へ解決します。"""

        alias = alias.strip()
        if not alias:
            return None
        alias_lower = alias.lower()
        all_names = list(self.switch._ports.keys()) + [
            interface.name for interface in self.switch.vlan_interfaces.values()
        ]
        for name in all_names:
            if name.lower() == alias_lower:
                return name

        alias_letters, alias_suffix = self._split_port_token(alias_lower)
        if not alias_letters:
            return None

        candidates: list[str] = []
        for name in all_names:
            name_lower = name.lower()
            letters, suffix = self._split_port_token(name_lower)
            if alias_suffix:
                if suffix != alias_suffix:
                    continue
            if not letters.startswith(alias_letters):
                continue
            candidates.append(name)

        if len(candidates) == 1:
            return candidates[0]
        return None

    def _parse_interface_range(self, text: str) -> list[str]:
        cleaned = text.replace(" ", "")
        if not cleaned:
            raise ValueError("invalid interface range")
        if "-" not in cleaned:
            name = self._resolve_interface_name(cleaned)
            if name is None:
                raise ValueError(f"unknown port: {cleaned}")
            return [name]

        start_alias, end_fragment = cleaned.split("-", 1)
        start_name = self._resolve_interface_name(start_alias)
        if start_name is None:
            raise ValueError(f"unknown port: {start_alias}")

        if not end_fragment:
            raise ValueError("invalid interface range end")
        if any(ch.isalpha() for ch in end_fragment) or "/" in end_fragment:
            end_alias_candidate = end_fragment
        else:
            if "/" in start_alias:
                prefix = start_alias[: start_alias.rfind("/") + 1]
                end_alias_candidate = f"{prefix}{end_fragment}"
            else:
                prefix, _ = self._split_port_token(start_alias.lower())
                end_alias_candidate = f"{prefix}{end_fragment}"
        end_name = self._resolve_interface_name(end_alias_candidate)
        if end_name is None:
            raise ValueError(f"unknown port: {end_alias_candidate}")

        port_names = list(self.switch._ports.keys())
        try:
            start_index = port_names.index(start_name)
            end_index = port_names.index(end_name)
        except ValueError as exc:
            raise ValueError("interface range includes unknown port") from exc

        if start_index <= end_index:
            selected = port_names[start_index : end_index + 1]
        else:
            selected = port_names[end_index : start_index + 1]
        return selected

    def _command_templates_for_mode(self) -> list[list[str]]:
        if self._mode == "user_exec":
            return self._user_command_templates()
        if self._mode == "priv_exec":
            return self._priv_command_templates()
        if self._mode == "config":
            return self._config_command_templates()
        if self._mode == "interface":
            return self._interface_command_templates()
        if self._mode == "interface_svi":
            return self._interface_svi_command_templates()
        if self._mode == "vlan":
            return self._vlan_command_templates()
        if self._mode == "line_console":
            return self._line_console_command_templates()
        if self._mode == "line_vty":
            return self._line_vty_command_templates()
        return []

    def _user_command_templates(self) -> list[list[str]]:
        commands = [
            ["enable"],
            ["exit"],
            ["quit"],
            ["help"],
            ["show", "clock"],
            ["show", "history"],
            ["show", "interfaces"],
            ["show", "interfaces", "status"],
            ["show", "interfaces", "description"],
            ["show", "interfaces", "switchport"],
            ["show", "interfaces", "trunk"],
            ["show", "interfaces", "<interface>"],
            ["show", "ip", "interface", "brief"],
            ["show", "logging"],
            ["show", "mac", "address-table"],
            ["show", "mac", "address-table", "dynamic"],
            ["show", "users"],
            ["show", "version"],
            ["show", "vlan"],
            ["show", "vlan", "brief"],
            ["show", "vlan", "id", "<vlan>"],
            ["show", "spanning-tree"],
        ]
        return commands

    def _priv_command_templates(self) -> list[list[str]]:
        commands = self._user_command_templates()
        commands.extend(
            [
                ["disable"],
                ["clear", "mac", "address-table"],
                ["configure", "terminal"],
                ["send", "frame", "<args>"],
                ["show", "running-config"],
                ["show", "startup-config"],
            ]
        )
        return commands

    def _config_command_templates(self) -> list[list[str]]:
        return [
            ["exit"],
            ["end"],
            ["help"],
            ["hostname", "<text>"],
            ["enable", "secret", "<password>"],
            ["no", "ip", "domain-lookup"],
            ["ip", "domain-lookup"],
            ["ip", "default-gateway", "<ip>"],
            ["interface", "<interface>"],
            ["interface", "range", "<range>"],
            ["interface", "vlan", "<vlan>"],
            ["spanning-tree", "mode", "rapid-pvst"],
            ["spanning-tree", "vlan", "<vlan>", "priority", "<priority>"],
            ["vlan", "<vlan>"],
            ["line", "console", "0"],
            ["line", "vty", "0", "4"],
            ["username", "<username>", "privilege", "<privilege>", "secret", "<password>"],
        ]

    def _interface_command_templates(self) -> list[list[str]]:
        return [
            ["description", "<text>"],
            ["exit"],
            ["end"],
            ["help"],
            ["no", "shutdown"],
            ["shutdown"],
            ["switchport", "mode", "access"],
            ["switchport", "access", "vlan", "<vlan>"],
            ["spanning-tree", "portfast"],
            ["no", "spanning-tree", "portfast"],
        ]

    def _interface_svi_command_templates(self) -> list[list[str]]:
        return [
            ["description", "<text>"],
            ["exit"],
            ["end"],
            ["help"],
            ["ip", "address", "<ip>", "<mask>"],
            ["no", "ip", "address"],
            ["no", "shutdown"],
            ["shutdown"],
        ]

    def _vlan_command_templates(self) -> list[list[str]]:
        return [
            ["exit"],
            ["end"],
            ["help"],
            ["name", "<text>"],
        ]

    def _line_console_command_templates(self) -> list[list[str]]:
        return [
            ["exit"],
            ["end"],
            ["help"],
            ["login", "local"],
            ["no", "login"],
        ]

    def _line_vty_command_templates(self) -> list[list[str]]:
        return [
            ["exit"],
            ["end"],
            ["help"],
            ["login", "local"],
            ["transport", "input", "ssh"],
            ["no", "login"],
        ]

    def complete(self, text: str, state: int) -> Optional[str]:
        if readline is None:  # pragma: no cover - 補完非対応環境
            return None
        if state == 0:
            buffer = readline.get_line_buffer()
            # libedit では get_endidx が存在しないためスライスは行わない
            self._completion_matches = self._collect_completion_candidates(buffer, text)
        if state < len(self._completion_matches):
            return self._completion_matches[state]
        return None

    def _collect_completion_candidates(self, buffer: str, text: str) -> list[str]:
        tokens = buffer.split()
        if buffer.endswith(" "):
            tokens.append("")

        if tokens:
            current_token = tokens[-1]
            if current_token == "":
                prefix_tokens = tokens[:-1]
                fragment = ""
            else:
                prefix_tokens = tokens[:-1]
                fragment = current_token
        else:
            prefix_tokens = []
            fragment = ""

        commands = self._command_templates_for_mode()
        candidates: set[str] = set()
        fragment_lower = fragment.lower()

        for template in commands:
            if not self._template_matches_prefix(prefix_tokens, template):
                continue
            if fragment:
                if len(template) <= len(prefix_tokens):
                    continue
                candidate = template[len(prefix_tokens)]
                candidates.update(
                    self._match_candidate_values(candidate, fragment_lower)
                )
            else:
                if len(template) <= len(prefix_tokens):
                    continue
                candidate = template[len(prefix_tokens)]
                values = self._match_candidate_values(candidate, "")
                if values:
                    candidates.update(values)

        return sorted(candidates)

    def _template_matches_prefix(
        self, prefix_tokens: list[str], template: list[str]
    ) -> bool:
        if len(prefix_tokens) > len(template):
            return False
        for index, token in enumerate(prefix_tokens):
            tmpl_token = template[index]
            if self._is_placeholder(tmpl_token):
                continue
            if not tmpl_token.startswith(token.lower()):
                return False
        return True

    def _match_candidate_values(
        self, candidate: str, fragment_lower: str
    ) -> set[str]:
        if self._is_placeholder(candidate):
            values = self._placeholder_values(candidate)
            return {value for value in values if value.lower().startswith(fragment_lower)}
        if candidate.startswith(fragment_lower):
            return {candidate}
        return set()

    @staticmethod
    def _is_placeholder(token: str) -> bool:
        return token.startswith("<") and token.endswith(">")

    def _placeholder_values(self, placeholder: str) -> list[str]:
        if placeholder == "<interface>":
            names = list(self.switch._ports.keys())
            names.extend(interface.name for interface in self.switch.vlan_interfaces.values())
            return sorted(names)
        if placeholder == "<vlan>":
            vlan_ids = {str(port.vlan) for port in self.switch._ports.values()}
            vlan_ids.update(str(vlan) for vlan in self.switch.vlan_interfaces.keys())
            vlan_ids.update(str(vlan_id) for vlan_id in self.switch.vlans.keys())
            return sorted(vlan_ids)
        if placeholder == "<privilege>":
            return ["15"]
        if placeholder == "<mask>":
            return ["255.255.255.0"]
        if placeholder == "<ip>":
            suggestions = []
            if self.switch.default_gateway:
                suggestions.append(self.switch.default_gateway)
            suggestions.append("192.168.1.1")
            return suggestions
        if placeholder == "<username>":
            return sorted(self.switch.user_accounts.keys())
        if placeholder == "<range>":
            return []
        if placeholder == "<priority>":
            return ["32768", "4096", "61440"]
        # テキストや任意引数は補完しない
        return []

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
        if self._mode == "interface_svi":
            return self._handle_interface_svi(command)
        if self._mode == "vlan":
            return self._handle_vlan(command)
        if self._mode == "line_console":
            return self._handle_line_console(command)
        if self._mode == "line_vty":
            return self._handle_line_vty(command)
        raise RuntimeError(f"invalid CLI mode: {self._mode}")

    # ------------------------------------------------------------------
    # EXEC モードのコマンド
    # ------------------------------------------------------------------
    def _handle_user_exec(self, command: str) -> str:
        if self._match_command(command, "enable") is not None:
            self._mode = "priv_exec"
            return ""
        if self._match_command(command, "disable") is not None:
            return "% Already in user EXEC mode."
        if any(
            self._match_command(command, pattern) is not None
            for pattern in ("show running-config", "show startup-config")
        ):
            return "% Command available in privileged EXEC mode."
        if self._match_command(command, "configure terminal") is not None:
            return "% Command available in privileged EXEC mode."
        if self._match_command(command, "clear mac address-table") is not None:
            return "% Command available in privileged EXEC mode."
        if self._match_command(command, "send frame", allow_suffix=True) is not None:
            return "% Command available in privileged EXEC mode."
        shared = self._handle_show_commands(command)
        if shared is not None:
            return shared
        return f"% Unknown command: {command}"

    def _handle_priv_exec(self, command: str) -> str:
        if self._match_command(command, "enable") is not None:
            return ""
        if self._match_command(command, "disable") is not None:
            self._mode = "user_exec"
            self._current_interface = None
            return ""
        if self._match_command(command, "configure terminal") is not None:
            self._mode = "config"
            return "Enter configuration commands, one per line. End with CNTL/Z."
        if self._match_command(command, "clear mac address-table") is not None:
            self.switch.clear_mac_table()
            return "MAC address table cleared."
        if self._match_command(command, "send frame", allow_suffix=True) is not None:
            return self._exec_send_frame(command)
        shared = self._handle_show_commands(command)
        if shared is not None:
            return shared
        return f"% Unknown command: {command}"

    def _handle_show_commands(self, command: str) -> Optional[str]:
        match = self._match_command(
            command, "show mac address-table", allow_suffix=True
        )
        if match is not None:
            remainder_tokens, _ = match
            if remainder_tokens:
                if len(remainder_tokens) != 1 or not "dynamic".startswith(
                    remainder_tokens[0]
                ):
                    return "% Unsupported parameters for show mac address-table"
            return self.switch.show_mac_address_table()

        if self._match_command(command, "show interfaces status") is not None:
            return self.switch.show_interfaces_status()

        if self._match_command(command, "show interfaces description") is not None:
            return self.switch.show_interfaces_description()

        match = self._match_command(
            command, "show interfaces switchport", allow_suffix=True
        )
        if match is not None:
            return self.switch.show_interfaces_switchport()

        match = self._match_command(command, "show interfaces trunk", allow_suffix=True)
        if match is not None:
            return self.switch.show_interfaces_trunk()

        match = self._match_command(command, "show interfaces", allow_suffix=True)
        if match is not None:
            remainder_tokens, _ = match
            if not remainder_tokens:
                return self.switch.show_interfaces_detail()
            if len(remainder_tokens) != 1:
                return "% Usage: show interfaces [interface]"
            interface_alias = remainder_tokens[0]
            interface = self._resolve_interface_name(interface_alias)
            if interface is None:
                return f"% unknown port: {interface_alias}"
            return self.switch.show_interfaces_detail(interface)

        if self._match_command(command, "show ip interface brief") is not None:
            return self.switch.show_ip_interface_brief()

        if self._match_command(command, "show vlan brief") is not None:
            return self.switch.show_vlan_brief()

        match = self._match_command(command, "show vlan id", allow_suffix=True)
        if match is not None:
            remainder_tokens, _ = match
            if len(remainder_tokens) != 1:
                return "% Usage: show vlan id <vlan-id>"
            try:
                vlan_id = int(remainder_tokens[0])
            except ValueError:
                return "% VLAN must be a numeric value"
            return self.switch.show_vlan_id(vlan_id)

        if self._match_command(command, "show vlan") is not None:
            return self.switch.show_vlan()

        if self._match_command(command, "show logging") is not None:
            return self.switch.show_event_log()

        if self._match_command(command, "show spanning-tree") is not None:
            return self.switch.show_spanning_tree()

        if self._match_command(command, "show running-config") is not None:
            return self.switch.show_running_config()

        if self._match_command(command, "show startup-config") is not None:
            return self.switch.show_startup_config()

        if self._match_command(command, "show version") is not None:
            return self.switch.show_version()

        if self._match_command(command, "show clock") is not None:
            return self._show_clock()

        if self._match_command(command, "show history") is not None:
            return self._show_history()

        if self._match_command(command, "show users") is not None:
            return self._show_users()

        unsupported_patterns = [
            "show arp",
            "show spanning-tree vlan",
            "show spanning-tree summary",
            "show cdp neighbors",
            "show cdp neighbors detail",
            "show lldp neighbors",
            "show lldp neighbors detail",
            "show inventory",
            "show environment",
            "show switch",
            "show processes cpu",
            "show processes memory",
            "show ip route",
            "show ip protocols",
        ]
        for pattern in unsupported_patterns:
            if self._match_command(command, pattern, allow_suffix=True) is not None:
                return "% Command not supported in this simulator."

        return None

    def _show_clock(self) -> str:
        now = datetime.now(UTC)
        return now.strftime("*%H:%M:%S UTC %a %d %b %Y")

    def _show_history(self) -> str:
        if not self._history:
            return "<no command history>"
        start = max(0, len(self._history) - 10)
        return "\n".join(self._history[start:])

    def _show_users(self) -> str:
        lines = [
            "    Line       User       Host(s)              Idle       Location",
            "   *    0 con 0            idle                 00:00:00",
        ]
        return "\n".join(lines)

    def _exec_send_frame(self, command: str) -> str:
        match = self._match_command(command, "send frame", allow_suffix=True)
        if match is None:
            return "Usage: send frame <src-mac> <dst-mac> <ingress-port> [payload]"
        remainder_tokens, _ = match
        if len(remainder_tokens) < 3:
            return "Usage: send frame <src-mac> <dst-mac> <ingress-port> [payload]"
        src_mac, dst_mac, ingress_port, *payload = remainder_tokens
        payload_text = " ".join(payload)
        try:
            frame = Frame(src_mac=src_mac, dst_mac=dst_mac, payload=payload_text)
            egress = self.switch.process_frame(ingress_port, frame)
        except ValueError as exc:
            return f"% {exc}"
        if not egress:
            return "Frame was dropped."
        lines = ["Frame forwarded to:"]
        for port in sorted(egress):
            lines.append(f"- {port}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # グローバル設定モードのコマンド
    # ------------------------------------------------------------------
    def _handle_config(self, command: str) -> str:
        if self._match_command(command, "exit") is not None:
            self._mode = "priv_exec"
            self._current_interface = None
            self._current_interfaces = []
            self._current_vlan = None
            self._current_svi = None
            self._current_line = None
            self._current_line_range = None
            return ""
        if self._match_command(command, "end") is not None:
            self._mode = "priv_exec"
            self._current_interface = None
            self._current_interfaces = []
            self._current_vlan = None
            self._current_svi = None
            self._current_line = None
            self._current_line_range = None
            return ""

        match = self._match_command(command, "hostname", allow_suffix=True)
        if match is not None:
            _, remainder_text = match
            if not remainder_text:
                return "Usage: hostname <name>"
            try:
                self.switch.set_hostname(remainder_text)
            except ValueError as exc:
                return f"% {exc}"
            return ""

        match = self._match_command(command, "enable secret", allow_suffix=True)
        if match is not None:
            _, remainder_text = match
            if not remainder_text:
                return "Usage: enable secret <password>"
            try:
                self.switch.set_enable_secret(remainder_text)
            except ValueError as exc:
                return f"% {exc}"
            return ""

        if self._match_command(command, "no ip domain-lookup") is not None:
            self.switch.set_domain_lookup(False)
            return ""

        if self._match_command(command, "ip domain-lookup") is not None:
            self.switch.set_domain_lookup(True)
            return ""

        match = self._match_command(command, "ip default-gateway", allow_suffix=True)
        if match is not None:
            remainder_tokens, _ = match
            if len(remainder_tokens) != 1:
                return "Usage: ip default-gateway <address>"
            gateway = remainder_tokens[0]
            if not validate_ipv4_address(gateway):
                return "% Invalid IPv4 address"
            try:
                self.switch.set_default_gateway(gateway)
            except ValueError as exc:
                return f"% {exc}"
            return ""

        match = self._match_command(command, "username", allow_suffix=True)
        if match is not None:
            remainder_tokens, _ = match
            if len(remainder_tokens) < 5:
                return "Usage: username <name> privilege <level> secret <password>"
            username = remainder_tokens[0]
            if not "privilege".startswith(remainder_tokens[1].lower()):
                return "Usage: username <name> privilege <level> secret <password>"
            try:
                privilege = int(remainder_tokens[2])
            except ValueError:
                return "% Privilege must be numeric"
            if len(remainder_tokens) < 5:
                return "Usage: username <name> privilege <level> secret <password>"
            if not "secret".startswith(remainder_tokens[3].lower()):
                return "Usage: username <name> privilege <level> secret <password>"
            secret = " ".join(remainder_tokens[4:])
            if not secret:
                return "Usage: username <name> privilege <level> secret <password>"
            try:
                self.switch.set_user_account(username, privilege, secret)
            except ValueError as exc:
                return f"% {exc}"
            return ""

        match = self._match_command(command, "spanning-tree mode", allow_suffix=True)
        if match is not None:
            remainder_tokens, _ = match
            if len(remainder_tokens) != 1:
                return "Usage: spanning-tree mode <mode>"
            mode = remainder_tokens[0]
            try:
                self.switch.set_stp_mode(mode)
            except ValueError as exc:
                return f"% {exc}"
            return ""

        match = self._match_command(command, "spanning-tree vlan", allow_suffix=True)
        if match is not None:
            remainder_tokens, _ = match
            if len(remainder_tokens) != 3:
                return "Usage: spanning-tree vlan <id> priority <value>"
            vlan_token, keyword, value = remainder_tokens
            if not "priority".startswith(keyword.lower()):
                return "Usage: spanning-tree vlan <id> priority <value>"
            try:
                vlan_id = int(vlan_token)
            except ValueError:
                return "% VLAN must be a numeric value"
            try:
                priority = int(value)
            except ValueError:
                return "% Priority must be numeric"
            try:
                self.switch.set_stp_vlan_priority(vlan_id, priority)
            except ValueError as exc:
                return f"% {exc}"
            return ""

        match = self._match_command(command, "vlan", allow_suffix=True)
        if match is not None:
            remainder_tokens, _ = match
            if len(remainder_tokens) != 1:
                return "Usage: vlan <vlan-id>"
            try:
                vlan_id = int(remainder_tokens[0])
            except ValueError:
                return "% VLAN must be a numeric value"
            try:
                self.switch.ensure_vlan(vlan_id)
            except ValueError as exc:
                return f"% {exc}"
            self._current_vlan = vlan_id
            self._current_interface = None
            self._current_interfaces = []
            self._current_svi = None
            self._mode = "vlan"
            return (
                f"Enter VLAN configuration commands for VLAN {vlan_id}. End with CNTL/Z."
            )

        match = self._match_command(command, "interface vlan", allow_suffix=True)
        if match is not None:
            remainder_tokens, _ = match
            if len(remainder_tokens) != 1:
                return "Usage: interface vlan <vlan-id>"
            try:
                vlan = int(remainder_tokens[0])
            except ValueError:
                return "% VLAN must be a numeric value"
            try:
                interface = self.switch.ensure_vlan_interface(vlan)
            except ValueError as exc:
                return f"% {exc}"
            self._current_svi = vlan
            self._current_interface = None
            self._current_interfaces = []
            self._mode = "interface_svi"
            return (
                f"Enter configuration commands for interface {interface.name}. End with CNTL/Z."
            )

        match = self._match_command(command, "interface range", allow_suffix=True)
        if match is not None:
            _, remainder_text = match
            if not remainder_text:
                return "Usage: interface range <start> - <end>"
            try:
                interfaces = self._parse_interface_range(remainder_text)
            except ValueError as exc:
                return f"% {exc}"
            self._current_interfaces = interfaces
            self._current_interface = interfaces[0]
            self._current_svi = None
            self._current_line = None
            self._current_line_range = None
            self._mode = "interface"
            return (
                "Enter configuration commands for interface range. End with CNTL/Z."
            )

        match = self._match_command(command, "line console", allow_suffix=True)
        if match is not None:
            remainder_tokens, _ = match
            if remainder_tokens and remainder_tokens != ["0"]:
                return "Usage: line console 0"
            self._mode = "line_console"
            self._current_line = "console"
            self._current_line_range = (0, 0)
            self._current_interface = None
            self._current_interfaces = []
            return "Enter line configuration commands. End with CNTL/Z."

        match = self._match_command(command, "line vty", allow_suffix=True)
        if match is not None:
            remainder_tokens, _ = match
            if len(remainder_tokens) not in {0, 2}:
                return "Usage: line vty 0 4"
            if len(remainder_tokens) == 2:
                start, end = remainder_tokens
            else:
                start, end = "0", "4"
            try:
                start_int = int(start)
                end_int = int(end)
            except ValueError:
                return "% Line numbers must be numeric"
            if start_int != 0 or end_int != 4:
                return "% Only vty 0 4 is supported in this simulator"
            self._mode = "line_vty"
            self._current_line = "vty"
            self._current_line_range = (start_int, end_int)
            self._current_interface = None
            self._current_interfaces = []
            return "Enter line configuration commands. End with CNTL/Z."

        match = self._match_command(command, "interface", allow_suffix=True)
        if match is not None:
            remainder_tokens, _ = match
            if not remainder_tokens:
                return "Usage: interface <name>"
            interface_alias = "".join(remainder_tokens)
            interface = self._resolve_interface_name(interface_alias)
            if interface is None:
                return f"% unknown port: {interface_alias}"
            self._current_interface = interface
            self._current_interfaces = [interface]
            self._mode = "interface"
            return f"Enter configuration commands for {interface}. End with CNTL/Z."
        return f"% Unknown configuration command: {command}"

    # ------------------------------------------------------------------
    # インターフェース設定モードのコマンド
    # ------------------------------------------------------------------
    def _handle_interface(self, command: str) -> str:
        if self._match_command(command, "exit") is not None:
            self._mode = "config"
            self._current_interface = None
            self._current_interfaces = []
            return ""
        if self._match_command(command, "end") is not None:
            self._mode = "priv_exec"
            self._current_interface = None
            self._current_interfaces = []
            return ""
        targets = self._current_interfaces or (
            [self._current_interface] if self._current_interface else []
        )
        if not targets:
            return "% No interface selected"
        if self._match_command(command, "no shutdown") is not None:
            for iface in targets:
                self.switch.set_port_admin_state(iface, True)
            return ""
        if self._match_command(command, "shutdown") is not None:
            for iface in targets:
                self.switch.set_port_admin_state(iface, False)
            return ""
        match = self._match_command(command, "description", allow_suffix=True)
        if match is not None:
            _, remainder_text = match
            description = remainder_text
            for iface in targets:
                self.switch.set_port_description(iface, description)
            return ""
        match = self._match_command(
            command, "switchport access vlan", allow_suffix=True
        )
        if match is not None:
            remainder_tokens, _ = match
            if len(remainder_tokens) != 1:
                return "Usage: switchport access vlan <vlan-id>"
            try:
                vlan = int(remainder_tokens[-1])
            except ValueError:
                return "% VLAN must be a numeric value"
            try:
                for iface in targets:
                    self.switch.set_port_vlan(iface, vlan)
            except ValueError as exc:
                return f"% {exc}"
            return ""
        if self._match_command(command, "switchport mode access") is not None:
            try:
                for iface in targets:
                    self.switch.set_port_mode(iface, "access")
            except ValueError as exc:
                return f"% {exc}"
            return ""
        if self._match_command(command, "spanning-tree portfast") is not None:
            try:
                for iface in targets:
                    self.switch.set_port_portfast(iface, True)
            except ValueError as exc:
                return f"% {exc}"
            return ""
        if self._match_command(command, "no spanning-tree portfast") is not None:
            try:
                for iface in targets:
                    self.switch.set_port_portfast(iface, False)
            except ValueError as exc:
                return f"% {exc}"
            return ""
        return f"% Unknown interface command: {command}"

    def _handle_interface_svi(self, command: str) -> str:
        if self._match_command(command, "exit") is not None:
            self._mode = "config"
            self._current_svi = None
            return ""
        if self._match_command(command, "end") is not None:
            self._mode = "priv_exec"
            self._current_svi = None
            return ""
        assert self._current_svi is not None
        vlan_id = self._current_svi
        if self._match_command(command, "no shutdown") is not None:
            self.switch.set_vlan_interface_admin_state(vlan_id, True)
            return ""
        if self._match_command(command, "shutdown") is not None:
            self.switch.set_vlan_interface_admin_state(vlan_id, False)
            return ""
        match = self._match_command(command, "ip address", allow_suffix=True)
        if match is not None:
            remainder_tokens, _ = match
            if len(remainder_tokens) != 2:
                return "Usage: ip address <address> <mask>"
            ip_addr, mask = remainder_tokens
            if not (validate_ipv4_address(ip_addr) and validate_ipv4_address(mask)):
                return "% Invalid IPv4 address"
            try:
                self.switch.set_vlan_interface_ip(vlan_id, ip_addr, mask)
            except ValueError as exc:
                return f"% {exc}"
            return ""
        if self._match_command(command, "no ip address") is not None:
            self.switch.clear_vlan_interface_ip(vlan_id)
            return ""
        match = self._match_command(command, "description", allow_suffix=True)
        if match is not None:
            _, remainder_text = match
            self.switch.set_vlan_interface_description(vlan_id, remainder_text)
            return ""
        return f"% Unknown interface command: {command}"

    def _handle_vlan(self, command: str) -> str:
        if self._match_command(command, "exit") is not None:
            self._mode = "config"
            self._current_vlan = None
            return ""
        if self._match_command(command, "end") is not None:
            self._mode = "priv_exec"
            self._current_vlan = None
            return ""
        if self._match_command(command, "help") is not None:
            return "Available VLAN commands: name <text>, exit"
        assert self._current_vlan is not None
        match = self._match_command(command, "name", allow_suffix=True)
        if match is not None:
            _, remainder_text = match
            if not remainder_text:
                return "Usage: name <vlan-name>"
            self.switch.set_vlan_name(self._current_vlan, remainder_text)
            return ""
        return f"% Unknown VLAN command: {command}"

    def _handle_line_console(self, command: str) -> str:
        if self._match_command(command, "exit") is not None:
            self._mode = "config"
            self._current_line = None
            self._current_line_range = None
            return ""
        if self._match_command(command, "end") is not None:
            self._mode = "priv_exec"
            self._current_line = None
            self._current_line_range = None
            return ""
        if self._match_command(command, "login local") is not None:
            self.switch.set_line_login_local("console", True)
            return ""
        if self._match_command(command, "no login") is not None:
            self.switch.set_line_login_local("console", False)
            return ""
        return f"% Unknown line command: {command}"

    def _handle_line_vty(self, command: str) -> str:
        if self._match_command(command, "exit") is not None:
            self._mode = "config"
            self._current_line = None
            self._current_line_range = None
            return ""
        if self._match_command(command, "end") is not None:
            self._mode = "priv_exec"
            self._current_line = None
            self._current_line_range = None
            return ""
        if self._match_command(command, "login local") is not None:
            self.switch.set_line_login_local("vty", True)
            return ""
        if self._match_command(command, "no login") is not None:
            self.switch.set_line_login_local("vty", False)
            return ""
        if self._match_command(command, "transport input ssh") is not None:
            self.switch.set_line_transport_input("ssh")
            return ""
        return f"% Unknown line command: {command}"


__all__ = ["SwitchCLI"]
