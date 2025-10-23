"""Utility helpers for address validation and formatting used by switch_sim."""

from __future__ import annotations

from datetime import UTC, datetime
import ipaddress

__all__ = ["normalize_mac", "validate_ipv4_address", "format_timestamp"]


def normalize_mac(mac: str) -> str:
    """Normalize a MAC address into lowercase ``aa:bb:cc:dd:ee:ff`` format.

    Accepts MAC addresses separated by colons, hyphens, or dotted hexadecimal,
    and raises ``ValueError`` if the input cannot be parsed.
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

    if len(parts) != 6 or any(len(part) != 2 for part in parts):
        raise ValueError(f"invalid MAC address: {mac}")

    try:
        octets = [int(part, 16) for part in parts]
    except ValueError as exc:
        raise ValueError(f"invalid MAC address: {mac}") from exc

    return ":".join(f"{octet:02x}" for octet in octets)


def validate_ipv4_address(value: str) -> bool:
    """Return ``True`` when ``value`` is a syntactically valid IPv4 address."""

    try:
        ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        return False
    return True


def format_timestamp(dt: datetime | None = None) -> str:
    """Format the provided UTC datetime (or the current time) as ``HH:MM:SS``."""

    if dt is None:
        dt = datetime.now(UTC)
    else:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        else:
            dt = dt.astimezone(UTC)
    return dt.strftime("%H:%M:%S")
