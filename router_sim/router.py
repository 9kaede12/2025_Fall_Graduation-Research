"""Router simulator module: reexports the main API."""

from router_sim.cli.dispatcher import RouterCLI
from router_sim.router_core import CiscoRouter

__all__ = ["CiscoRouter", "RouterCLI"]
