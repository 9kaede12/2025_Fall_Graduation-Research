from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network


@dataclass(frozen=True)
class OspfNetwork:
    network: IPv4Network
    wildcard: IPv4Address
    area: int

    def description(self) -> str:
        return (
            f"{self.network.network_address.exploded} "
            f"{self.wildcard.exploded} area {self.area}"
        )

