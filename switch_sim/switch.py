"""教育用イーサネットスイッチの基礎的なシミュレーション機能を提供します。

本モジュールの目的は、Cisco IOS に似た小さなコマンドラインインターフェースとともに、
簡潔で表現力のあるレイヤ 2 スイッチのモデルを提供することです。実装は初学者向け
ネットワーク演習で重要となる以下の機能に焦点を当てています。

* 管理状態と VLAN 割り当てを備えたポート抽象化。
* エージングタイマーと転送判断を伴う MAC アドレス学習。
* 稼働中の設定を確認・変更するための簡易コマンド。
* スイッチの挙動理解を助けるミニイベントログ。

このシミュレーションは外部依存を持たず、``python -m switch_sim.switch`` で直接実行できます。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import ipaddress
from typing import Dict, Iterable, Optional

try:  # pragma: no cover - 環境依存
    import readline
except ImportError:  # pragma: no cover - Windows 想定
    readline = None


DEFAULT_AGING_TIME = timedelta(minutes=5)


def normalize_mac(mac: str) -> str:
    """MAC アドレスを ``aa:bb:cc:dd:ee:ff`` 形式に正規化します。

    コロン、ハイフン、またはドット（``aaaa.bbbb.cccc``）で区切られた入力を受け付け、
    形式が正しくない場合は ``ValueError`` を送出して呼び出し元が適切なエラーを表示できるようにします。
    """

    mac = mac.strip().lower()
    if ":" in mac:
        parts = mac.split(":")
    elif "-" in mac:
        parts = mac.split("-")
    elif "." in mac:
        mac = mac.replace(".", "")
        parts = [mac[i : i + 2] for i in range(0, len(mac), 2)]
    else:
        parts = [mac[i : i + 2] for i in range(0, len(mac), 2)]

    if len(parts) != 6 or any(len(p) != 2 for p in parts):
        raise ValueError(f"invalid MAC address: {mac}")

    try:
        ints = [int(p, 16) for p in parts]
    except ValueError as exc:  # pragma: no cover - 防御的プログラミング
        raise ValueError(f"invalid MAC address: {mac}") from exc

    return ":".join(f"{part:02x}" for part in ints)


def validate_ipv4_address(value: str) -> bool:
    """渡された文字列が IPv4 アドレス形式か検証します。"""

    try:
        ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        return False
    return True


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
class MacTableEntry:
    """動的な MAC アドレステーブルエントリを表現します。"""

    vlan: int
    port: str
    learned_at: datetime

    def is_expired(self, now: datetime, aging_time: timedelta) -> bool:
        return now - self.learned_at >= aging_time


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


@dataclass
class Vlan:
    """VLAN の属性を保持します。"""

    vlan_id: int
    name: str = ""

    def display_name(self) -> str:
        return self.name or f"VLAN{self.vlan_id}"


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

    # ------------------------------------------------------------------
    # 設定ヘルパー
    # ------------------------------------------------------------------
    def set_port_admin_state(self, port: str, admin_up: bool) -> None:
        port_obj = self._require_port(port)
        port_obj.admin_up = admin_up
        self._log(f"Port {port} administratively {'up' if admin_up else 'down'}")

    def set_port_vlan(self, port: str, vlan: int) -> None:
        if vlan <= 0:
            raise ValueError("VLAN IDs must be positive integers")
        self.ensure_vlan(vlan)
        port_obj = self._require_port(port)
        port_obj.vlan = vlan
        self._log(f"Port {port} assigned to VLAN {vlan}")

    def set_port_description(self, port: str, description: str) -> None:
        port_obj = self._require_port(port)
        port_obj.description = description
        self._log(f"Description set on {port}: {description}")

    def set_port_mode(self, port: str, mode: str) -> None:
        normalized = mode.lower()
        if normalized != "access":
            raise ValueError("only access mode is supported in this simulator")
        port_obj = self._require_port(port)
        port_obj.mode = normalized
        self._log(f"Port {port} mode set to {normalized}")

    def set_port_portfast(self, port: str, enabled: bool) -> None:
        port_obj = self._require_port(port)
        if port_obj.mode != "access" and enabled:
            raise ValueError("portfast is only valid on access ports")
        self.port_portfast[port] = enabled
        state = "enabled" if enabled else "disabled"
        self._log(f"Port {port} spanning-tree portfast {state}")

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
        if vlan <= 0:
            raise ValueError("VLAN IDs must be positive integers")
        self.ensure_vlan(vlan)
        interface = self.vlan_interfaces.get(vlan)
        if interface is None:
            name = f"Vlan{vlan}"
            interface = VlanInterface(vlan=vlan, name=name)
            self.vlan_interfaces[vlan] = interface
            self._log(f"Created interface {name}")
        return interface

    def set_vlan_interface_ip(self, vlan: int, ip: str, mask: str) -> None:
        if not validate_ipv4_address(ip) or not validate_ipv4_address(mask):
            raise ValueError("invalid IPv4 address or mask")
        interface = self.ensure_vlan_interface(vlan)
        interface.ip_address = ip
        interface.subnet_mask = mask
        self._log(f"Interface {interface.name} IP set to {ip} {mask}")

    def clear_vlan_interface_ip(self, vlan: int) -> None:
        interface = self.ensure_vlan_interface(vlan)
        interface.ip_address = None
        interface.subnet_mask = None
        self._log(f"Interface {interface.name} IP address cleared")

    def set_vlan_interface_admin_state(self, vlan: int, admin_up: bool) -> None:
        interface = self.ensure_vlan_interface(vlan)
        interface.admin_up = admin_up
        self._log(
            f"Interface {interface.name} administratively {'up' if admin_up else 'down'}"
        )

    def set_vlan_interface_description(self, vlan: int, description: str) -> None:
        interface = self.ensure_vlan_interface(vlan)
        interface.description = description
        self._log(f"Description set on {interface.name}: {description}")

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
        if vlan <= 0:
            raise ValueError("VLAN IDs must be positive integers")
        vlan_obj = self.vlans.get(vlan)
        if vlan_obj is None:
            vlan_obj = Vlan(vlan_id=vlan)
            self.vlans[vlan] = vlan_obj
            self._log(f"VLAN {vlan} created")
        return vlan_obj

    def set_vlan_name(self, vlan: int, name: str) -> None:
        if vlan <= 0:
            raise ValueError("VLAN IDs must be positive integers")
        vlan_obj = self.ensure_vlan(vlan)
        vlan_obj.name = name
        self._log(f"VLAN {vlan} named {name}")

    def set_stp_mode(self, mode: str) -> None:
        normalized = mode.lower()
        if normalized not in {"rapid-pvst"}:
            raise ValueError("only rapid-pvst mode is supported")
        self.stp_mode = normalized
        self._log(f"Spanning-tree mode set to {normalized}")

    def set_stp_vlan_priority(self, vlan: int, priority: int) -> None:
        if vlan <= 0:
            raise ValueError("VLAN IDs must be positive integers")
        if priority < 0 or priority > 61440 or priority % 4096 != 0:
            raise ValueError("priority must be between 0 and 61440 in steps of 4096")
        self.ensure_vlan(vlan)
        self.stp_vlan_priority[vlan] = priority
        self._log(f"Spanning-tree VLAN {vlan} priority set to {priority}")

    def port_portfast_enabled(self, port: str) -> bool:
        return self.port_portfast.get(port, False)

    # ------------------------------------------------------------------
    # 運用ヘルパー
    # ------------------------------------------------------------------
    def process_frame(self, ingress_port: str, frame: Frame) -> Dict[str, Frame]:
        """フレームを処理し、送信されるフレームを返します。

        MAC テーブルを更新し、VLAN フィルタリングを適用したうえで転送すべきポートを決定します。
        返却される辞書は送信ポート名をキーにし、そのポートから送出されるフレームを保持します。
        """

        port = self._require_port(ingress_port)
        if not port.admin_up:
            self._log(
                f"Frame from {frame.src_mac} dropped: ingress port {ingress_port} is down"
            )
            return {}

        self._age_mac_table()

        # 送信元 MAC を学習
        entry = self.mac_table.get(frame.src_mac)
        if entry is None or entry.port != ingress_port or entry.vlan != port.vlan:
            self.mac_table[frame.src_mac] = MacTableEntry(
                vlan=port.vlan, port=ingress_port, learned_at=datetime.now(UTC)
            )
            self._log(
                f"Learned {frame.src_mac} on {ingress_port} (VLAN {port.vlan})"
            )

        # 転送先を決定
        egress_ports: Dict[str, Frame] = {}
        if frame.dst_mac == "ff:ff:ff:ff:ff:ff":
            decision = "Broadcast frame flooded"
            candidate_ports = self._ports.values()
        else:
            dst_entry = self.mac_table.get(frame.dst_mac)
            if dst_entry and dst_entry.vlan == port.vlan:
                candidate_ports = [self._ports[dst_entry.port]]
                decision = f"Unicast frame forwarded to {dst_entry.port}"
            else:
                candidate_ports = self._ports.values()
                decision = "Unknown destination: frame flooded"

        for candidate in candidate_ports:
            if candidate.name == ingress_port:
                continue
            if candidate.vlan != port.vlan:
                continue
            if not candidate.admin_up:
                continue
            egress_ports[candidate.name] = frame

        self._log(decision)
        return egress_ports

    # ------------------------------------------------------------------
    # show コマンド用ヘルパー
    # ------------------------------------------------------------------
    def show_mac_address_table(self) -> str:
        self._age_mac_table()
        lines = ["VLAN    MAC Address        Type        Ports"]
        for mac, entry in sorted(self.mac_table.items()):
            lines.append(
                f"{entry.vlan:<7}{mac:<18}{'dynamic':<12}{entry.port}"
            )
        if len(lines) == 1:
            lines.append("<no dynamic entries>")
        return "\n".join(lines)

    def show_interfaces_status(self) -> str:
        lines = ["Port            Status                  VLAN  Description"]
        interfaces = list(self._ports.values()) + list(self.vlan_interfaces.values())
        interfaces.sort(key=lambda iface: iface.name)
        for port in interfaces:
            lines.append(
                f"{port.name:<15}{port.status():<24}{port.vlan:<5} {port.description}"
            )
        return "\n".join(lines)

    def show_event_log(self, limit: Optional[int] = None) -> str:
        if limit is None:
            events = self.event_log
        else:
            events = self.event_log[-limit:]
        return "\n".join(events) if events else "<no events>"

    def show_interfaces_detail(self, interface: Optional[str] = None) -> str:
        if interface is not None:
            ports = [self._get_interface_by_name(interface)]
        else:
            ports = list(self._ports.values()) + list(self.vlan_interfaces.values())
            ports.sort(key=lambda iface: iface.name)
        lines: list[str] = []
        for port in ports:
            if isinstance(port, VlanInterface):
                status_line = (
                    f"{port.name} is up"
                    if port.admin_up
                    else f"{port.name} is administratively down"
                )
            else:
                status_line = (
                    f"{port.name} is connected"
                    if port.admin_up
                    else f"{port.name} is administratively down"
                )
            lines.append(status_line)
            lines.append(f"  VLAN {port.vlan}")
            if isinstance(port, VlanInterface):
                if port.ip_address and port.subnet_mask:
                    lines.append(
                        f"  Internet address is {port.ip_address}/{port.subnet_mask}"
                    )
                else:
                    lines.append("  Internet address is unassigned")
            description = port.description or "<no description>"
            lines.append(f"  Description: {description}")
            lines.append("")
        if not lines:
            return "<no interfaces>"
        return "\n".join(lines).rstrip()

    def show_interfaces_description(self) -> str:
        lines = ["Interface        Status          Description"]
        interfaces = list(self._ports.values()) + list(self.vlan_interfaces.values())
        interfaces.sort(key=lambda iface: iface.name)
        for port in interfaces:
            status = port.status()
            description = port.description or ""
            lines.append(f"{port.name:<16}{status:<16}{description}")
        return "\n".join(lines)

    def show_ip_interface_brief(self) -> str:
        lines = [
            "Interface              IP-Address      OK? Method Status                Protocol"
        ]
        interfaces = list(self._ports.values()) + list(self.vlan_interfaces.values())
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

    def show_vlan_brief(self) -> str:
        return self.show_vlan()

    def show_vlan_id(self, vlan_id: int) -> str:
        vlan = self.vlans.get(vlan_id)
        if vlan is None:
            return f"% VLAN {vlan_id} not found."
        members = [
            port.name for port in self._ports.values() if port.vlan == vlan_id
        ]
        lines = [
            "VLAN Name                             Status    Ports",
            f"{vlan_id:<4} {vlan.display_name():<30} active    {', '.join(sorted(members)) if members else ''}",
        ]
        return "\n".join(lines)

    def show_interfaces_switchport(self) -> str:
        lines: list[str] = []
        for port in self._ports.values():
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
        self.mac_table.clear()
        self._log("MAC address table cleared")

    def _require_port(self, port: str) -> Port:
        try:
            return self._ports[port]
        except KeyError as exc:  # pragma: no cover - テストで検証済み
            raise ValueError(f"unknown port: {port}") from exc

    def _get_interface_by_name(self, name: str):
        if name in self._ports:
            return self._ports[name]
        lowered = name.lower()
        for port_name, port in self._ports.items():
            if port_name.lower() == lowered:
                return port
        lowered = name.lower()
        if lowered.startswith("vlan"):
            try:
                vlan_id = int(lowered[4:])
            except ValueError as exc:
                raise ValueError(f"unknown interface: {name}") from exc
            interface = self.vlan_interfaces.get(vlan_id)
            if interface is not None:
                return interface
        for interface in self.vlan_interfaces.values():
            if interface.name.lower() == lowered:
                return interface
        raise ValueError(f"unknown interface: {name}")

    def _age_mac_table(self) -> None:
        now = datetime.now(UTC)
        to_delete = [
            mac
            for mac, entry in self.mac_table.items()
            if entry.is_expired(now, self.mac_table_aging)
        ]
        for mac in to_delete:
            del self.mac_table[mac]
            self._log(f"Aged out {mac} from MAC table")

    def _log(self, message: str) -> None:
        timestamp = datetime.now(UTC).strftime("%H:%M:%S")
        self.event_log.append(f"[{timestamp}] {message}")


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


def _default_switch() -> EthernetSwitch:
    ports = [f"FastEthernet0/{i}" for i in range(1, 5)]
    return EthernetSwitch(name="Switch1", ports=ports)


def _repl(cli: SwitchCLI) -> None:
    if readline is not None:  # pragma: no cover - 対話設定
        try:
            if readline.__doc__ and "libedit" in readline.__doc__:
                readline.parse_and_bind("bind ^I rl_complete")
            else:
                readline.parse_and_bind("tab: complete")
        except Exception:  # pragma: no cover - libedit 差異
            pass
        for command in ("set show-all-if-ambiguous on", "set completion-ignore-case on"):
            try:
                readline.parse_and_bind(command)
            except Exception:  # pragma: no cover - 環境依存
                pass
        try:
            readline.set_completer(lambda text, state: cli.complete(text, state))
            readline.set_completer_delims(" \t\n")
        except Exception:  # pragma: no cover - 環境依存
            pass
    print("Simple switch CLI. Type 'help' for available commands or 'quit' to exit.")
    while True:
        hostname = cli.switch.name
        if cli._mode == "user_exec":
            prompt = f"{hostname}> "
        elif cli._mode == "priv_exec":
            prompt = f"{hostname}# "
        elif cli._mode == "config":
            prompt = f"{hostname}(config)# "
        elif cli._mode in {"interface", "interface_svi"}:
            prompt = f"{hostname}(config-if)# "
        elif cli._mode == "vlan":
            prompt = f"{hostname}(config-vlan)# "
        elif cli._mode in {"line_console", "line_vty"}:
            prompt = f"{hostname}(config-line)# "
        else:
            prompt = f"{hostname}# "
        try:
            command = input(prompt)
        except EOFError:  # pragma: no cover - 対話支援用ヘルパー
            print()
            break
        command = command.strip()
        if cli._mode in {"user_exec", "priv_exec"} and (
            cli._match_command(command, "quit") is not None
            or cli._match_command(command, "exit") is not None
        ):
            break
        if cli._match_command(command, "help") is not None:
            print(_help_text())
            continue
        output = cli.execute(command)
        if output:
            print(output)

    if readline is not None:  # pragma: no cover - 終了時後片付け
        try:
            readline.set_completer(None)
        except Exception:
            pass


def _help_text() -> str:
    return (
        "User EXEC commands:\n"
        "  enable                        Enter privileged EXEC mode\n"
        "  show interfaces               Display detailed port information\n"
        "  show version                  Display software information\n"
        "  show mac address-table         Display learned MAC addresses\n"
        "  show interfaces status         Show port operational state\n"
        "  show vlan                      List VLAN membership\n"
        "  show logging                   Print recent events\n"
        "\n"
        "Privileged EXEC additional commands:\n"
        "  disable                       Return to user EXEC mode\n"
        "  clear mac address-table        Remove all learned addresses\n"
        "  show running-config            Display current configuration\n"
        "  show startup-config            Display saved configuration\n"
        "  send frame <src> <dst> <port>  Inject a frame into the switch\n"
        "  configure terminal             Enter configuration mode\n"
        "\n"
        "Configuration mode commands:\n"
        "  interface <name>               Select interface configuration\n"
        "  exit                           Return to privileged EXEC mode\n"
        "\n"
        "Interface configuration commands:\n"
        "  description <text>             Set port description\n"
        "  shutdown | no shutdown         Disable/enable the port\n"
        "  switchport access vlan <id>    Change the access VLAN\n"
        "  exit                           Return to config mode\n"
    )


if __name__ == "__main__":  # pragma: no cover - 手動実行用エントリポイント
    switch = _default_switch()
    cli = SwitchCLI(switch)
    _repl(cli)
