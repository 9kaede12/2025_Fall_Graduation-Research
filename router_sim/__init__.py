"""Educational Cisco router simulator package."""

from router_sim.router_core import CiscoRouter
from router_sim.cli.dispatcher import RouterCLI

__all__ = ["CiscoRouter", "RouterCLI"]
