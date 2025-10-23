"""Spanning Tree Protocol helpers for the educational Ethernet switch simulator."""

from __future__ import annotations

from typing import TYPE_CHECKING, List

__all__ = ["STPManager"]

if TYPE_CHECKING:  # pragma: no cover - 型チェック専用
    from switch_sim.switch_core import EthernetSwitch


class STPManager:
    """Rapid-PVST 設定や状態表示を担当するヘルパーです。"""

    def __init__(self, switch: "EthernetSwitch") -> None:
        self._switch = switch

    def set_mode(self, mode: str) -> None:
        normalized = mode.lower()
        if normalized not in {"rapid-pvst"}:
            raise ValueError("only rapid-pvst mode is supported")
        self._switch.stp_mode = normalized
        self._switch._log(f"Spanning-tree mode set to {normalized}")

    def set_vlan_priority(self, vlan: int, priority: int) -> None:
        if priority < 0 or priority > 61440 or priority % 4096 != 0:
            raise ValueError("priority must be between 0 and 61440 in steps of 4096")
        self._switch.ensure_vlan(vlan)
        self._switch.stp_vlan_priority[vlan] = priority
        self._switch._log(f"Spanning-tree VLAN {vlan} priority set to {priority}")

    def show_spanning_tree(self) -> str:
        lines = [
            f"Spanning tree enabled protocol {self._switch.stp_mode.upper()}",
        ]
        vlan_ids = sorted(self._switch.vlans.keys())
        if not vlan_ids:
            vlan_ids = [1]
        for vlan_id in vlan_ids:
            vlan = self._switch.vlans[vlan_id]
            priority = self._switch.stp_vlan_priority.get(vlan_id, 32768 + vlan_id)
            lines.append(f"\nVLAN{vlan_id:04d}")
            lines.append(f"  Bridge Identifier has priority {priority}")
            portfast_ports = [
                port for port in sorted(self._switch._ports) if self._switch.port_portfast_enabled(port)
            ]
            if portfast_ports:
                lines.append("  Portfast enabled on:")
                for port in portfast_ports:
                    lines.append(f"    {port}")
            else:
                lines.append("  Portfast enabled on: <none>")
        return "\n".join(lines)
