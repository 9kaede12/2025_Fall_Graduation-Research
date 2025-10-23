"""Frame ingress and egress processing for the educational switch simulator."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Dict, TYPE_CHECKING

__all__ = ["process_frame"]

if TYPE_CHECKING:  # pragma: no cover - 型チェック専用
    from switch_sim.switch_core import EthernetSwitch, Frame


def process_frame(
    switch: "EthernetSwitch", ingress_port: str, frame: "Frame"
) -> Dict[str, "Frame"]:
    """フレームを処理し、転送すべき出力ポートとフレームを返します。"""

    port = switch._interface_manager.require_port(ingress_port)
    if not port.admin_up:
        switch._log(
            f"Frame from {frame.src_mac} dropped: ingress port {ingress_port} is down"
        )
        return {}

    switch._mac_manager.age_entries()

    switch._mac_manager.learn(frame.src_mac, port.vlan, ingress_port)

    egress_ports: Dict[str, "Frame"] = {}
    if frame.dst_mac == "ff:ff:ff:ff:ff:ff":
        decision = "Broadcast frame flooded"
        candidate_ports = switch._ports.values()
    else:
        dst_entry = switch._mac_manager.lookup(frame.dst_mac)
        if dst_entry and dst_entry.vlan == port.vlan:
            candidate_ports = [switch._ports[dst_entry.port]]
            decision = f"Unicast frame forwarded to {dst_entry.port}"
        else:
            candidate_ports = switch._ports.values()
            decision = "Unknown destination: frame flooded"

    for candidate in candidate_ports:
        if candidate.name == ingress_port:
            continue
        if candidate.vlan != port.vlan:
            continue
        if not candidate.admin_up:
            continue
        egress_ports[candidate.name] = frame

    switch._log(decision)
    return egress_ports
