"""Switch simulator module: reexports the main API."""

from switch_sim.switch_core import EthernetSwitch
from switch_sim.modules.cli import SwitchCLI

__all__ = ["EthernetSwitch", "SwitchCLI"]
