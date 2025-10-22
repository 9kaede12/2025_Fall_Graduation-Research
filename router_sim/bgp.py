from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network


@dataclass(frozen=True)
class BgpNeighbor:
    address: IPv4Address
    remote_as: int

    def description(self) -> str:
        return f"{self.address.exploded} remote-as {self.remote_as}"


@dataclass(frozen=True)
class BgpNetwork:
    prefix: IPv4Network

    def description(self) -> str:
        return self.prefix.with_prefixlen

