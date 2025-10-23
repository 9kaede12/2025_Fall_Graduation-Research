"""Entry point for running the educational Ethernet switch simulator interactively."""

from __future__ import annotations

try:  # pragma: no cover - 環境依存
    import readline
except ImportError:  # pragma: no cover - Windows 想定
    readline = None

from switch_sim.modules.cli import SwitchCLI
from switch_sim.switch_core import EthernetSwitch


def _default_switch() -> EthernetSwitch:
    ports = [f"FastEthernet0/{i}" for i in range(1, 5)]
    return EthernetSwitch(name="Switch1", ports=ports)


def _repl(cli: SwitchCLI) -> None:
    if readline is not None:  # pragma: no cover - 対話設定
        try:
            if readline.__doc__ and "libedit" in readline.__doc__:
                readline.parse_and_bind("bind ^I rl_complete")
            else:
                readline.parse_and_bind("tab: complete")
        except Exception:  # pragma: no cover - libedit 差異
            pass
        for command in ("set show-all-if-ambiguous on", "set completion-ignore-case on"):
            try:
                readline.parse_and_bind(command)
            except Exception:  # pragma: no cover - 環境依存
                pass
        try:
            readline.set_completer(lambda text, state: cli.complete(text, state))
            readline.set_completer_delims(" \t\n")
        except Exception:  # pragma: no cover - 環境依存
            pass
    print("Simple switch CLI. Type 'help' for available commands or 'quit' to exit.")
    while True:
        hostname = cli.switch.name
        if cli._mode == "user_exec":
            prompt = f"{hostname}> "
        elif cli._mode == "priv_exec":
            prompt = f"{hostname}# "
        elif cli._mode == "config":
            prompt = f"{hostname}(config)# "
        elif cli._mode in {"interface", "interface_svi"}:
            prompt = f"{hostname}(config-if)# "
        elif cli._mode == "vlan":
            prompt = f"{hostname}(config-vlan)# "
        elif cli._mode in {"line_console", "line_vty"}:
            prompt = f"{hostname}(config-line)# "
        else:
            prompt = f"{hostname}# "
        try:
            command = input(prompt)
        except EOFError:  # pragma: no cover - 対話支援用ヘルパー
            print()
            break
        command = command.strip()
        if cli._mode in {"user_exec", "priv_exec"} and (
            cli._match_command(command, "quit") is not None
            or cli._match_command(command, "exit") is not None
        ):
            break
        if cli._match_command(command, "help") is not None:
            print(_help_text())
            continue
        output = cli.execute(command)
        if output:
            print(output)

    if readline is not None:  # pragma: no cover - 終了時後片付け
        try:
            readline.set_completer(None)
        except Exception:
            pass


def _help_text() -> str:
    return (
        "User EXEC commands:\n"
        "  enable                        Enter privileged EXEC mode\n"
        "  show interfaces               Display detailed port information\n"
        "  show version                  Display software information\n"
        "  show mac address-table         Display learned MAC addresses\n"
        "  show interfaces status         Show port operational state\n"
        "  show vlan                      List VLAN membership\n"
        "  show logging                   Print recent events\n"
        "\n"
        "Privileged EXEC additional commands:\n"
        "  disable                       Return to user EXEC mode\n"
        "  clear mac address-table        Remove all learned addresses\n"
        "  show running-config            Display current configuration\n"
        "  show startup-config            Display saved configuration\n"
        "  send frame <src> <dst> <port>  Inject a frame into the switch\n"
        "  configure terminal             Enter configuration mode\n"
        "\n"
        "Configuration mode commands:\n"
        "  interface <name>               Select interface configuration\n"
        "  exit                           Return to privileged EXEC mode\n"
        "\n"
        "Interface configuration commands:\n"
        "  description <text>             Set port description\n"
        "  shutdown | no shutdown         Disable/enable the port\n"
        "  switchport access vlan <id>    Change the access VLAN\n"
        "  exit                           Return to config mode\n"
    )


if __name__ == "__main__":  # pragma: no cover - 手動実行用エントリポイント
    switch = _default_switch()
    cli = SwitchCLI(switch)
    _repl(cli)
