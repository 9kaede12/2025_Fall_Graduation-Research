"""VLAN management helpers for the educational Ethernet switch simulator."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, TYPE_CHECKING, List

__all__ = ["Vlan", "VlanManager"]

if TYPE_CHECKING:  # pragma: no cover - 型チェック専用
    from switch_sim.switch_core import EthernetSwitch


@dataclass
class Vlan:
    """VLAN の属性を保持します。"""

    vlan_id: int
    name: str = ""

    def display_name(self) -> str:
        return self.name or f"VLAN{self.vlan_id}"


class VlanManager:
    """VLAN 定義や表示処理を担当するヘルパーです。"""

    def __init__(self, switch: "EthernetSwitch") -> None:
        self._switch = switch

    def ensure_vlan(self, vlan: int) -> Vlan:
        if vlan <= 0:
            raise ValueError("VLAN IDs must be positive integers")
        vlan_obj = self._switch.vlans.get(vlan)
        if vlan_obj is None:
            vlan_obj = Vlan(vlan_id=vlan)
            self._switch.vlans[vlan] = vlan_obj
            self._switch._log(f"VLAN {vlan} created")
        return vlan_obj

    def set_vlan_name(self, vlan: int, name: str) -> None:
        vlan_obj = self.ensure_vlan(vlan)
        vlan_obj.name = name
        self._switch._log(f"VLAN {vlan} named {name}")

    def show_vlan(self) -> str:
        vlan_members: Dict[int, List[str]] = {}
        for port in self._switch._ports.values():
            vlan_members.setdefault(port.vlan, []).append(port.name)
        lines = ["VLAN Name                             Status    Ports"]
        vlan_ids = sorted(set(self._switch.vlans.keys()) | set(vlan_members.keys()))
        if not vlan_ids:
            lines.append("<no VLANs>")
            return "\n".join(lines)
        for vlan_id in vlan_ids:
            vlan = self._switch.vlans.get(vlan_id) or Vlan(vlan_id=vlan_id)
            ports = ", ".join(sorted(vlan_members.get(vlan_id, [])))
            lines.append(f"{vlan_id:<4} {vlan.display_name():<30} active    {ports}")
        return "\n".join(lines)

    def show_vlan_id(self, vlan_id: int) -> str:
        vlan = self._switch.vlans.get(vlan_id)
        if vlan is None:
            return f"% VLAN {vlan_id} not found."
        members = [
            port.name for port in self._switch._ports.values() if port.vlan == vlan_id
        ]
        lines = [
            "VLAN Name                             Status    Ports",
            f"{vlan_id:<4} {vlan.display_name():<30} active    {', '.join(sorted(members)) if members else ''}",
        ]
        return "\n".join(lines)
