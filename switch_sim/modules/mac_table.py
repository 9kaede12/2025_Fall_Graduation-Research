"""MAC address table management for the educational switch simulator."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Dict, Optional, TYPE_CHECKING

__all__ = ["MacTableEntry", "MacTableManager"]

if TYPE_CHECKING:  # pragma: no cover - 型チェック専用
    from switch_sim.switch_core import EthernetSwitch


@dataclass
class MacTableEntry:
    """動的な MAC アドレステーブルエントリを表現します。"""

    vlan: int
    port: str
    learned_at: datetime

    def is_expired(self, now: datetime, aging_time: timedelta) -> bool:
        return now - self.learned_at >= aging_time


class MacTableManager:
    """MAC アドレス学習と表示を担当するヘルパーです。"""

    def __init__(self, switch: "EthernetSwitch") -> None:
        self._switch = switch

    @property
    def table(self) -> Dict[str, MacTableEntry]:
        return self._switch.mac_table

    def age_entries(self) -> None:
        now = datetime.now(UTC)
        to_delete = [
            mac
            for mac, entry in self.table.items()
            if entry.is_expired(now, self._switch.mac_table_aging)
        ]
        for mac in to_delete:
            del self.table[mac]
            self._switch._log(f"Aged out {mac} from MAC table")

    def learn(self, mac: str, vlan: int, port: str) -> None:
        entry = self.table.get(mac)
        if entry is None or entry.port != port or entry.vlan != vlan:
            self.table[mac] = MacTableEntry(
                vlan=vlan,
                port=port,
                learned_at=datetime.now(UTC),
            )
            self._switch._log(f"Learned {mac} on {port} (VLAN {vlan})")

    def lookup(self, mac: str) -> Optional[MacTableEntry]:
        return self.table.get(mac)

    def clear(self) -> None:
        self.table.clear()
        self._switch._log("MAC address table cleared")

    def render(self) -> str:
        self.age_entries()
        lines = ["VLAN    MAC Address        Type        Ports"]
        for mac, entry in sorted(self.table.items()):
            lines.append(f"{entry.vlan:<7}{mac:<18}{'dynamic':<12}{entry.port}")
        if len(lines) == 1:
            lines.append("<no dynamic entries>")
        return "\n".join(lines)
