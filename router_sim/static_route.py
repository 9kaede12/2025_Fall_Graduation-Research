from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network


@dataclass(frozen=True)
class StaticRoute:
    network: IPv4Network
    next_hop: IPv4Address

    def description(self) -> str:
        return f"{self.network.with_prefixlen} via {self.next_hop.exploded}"

