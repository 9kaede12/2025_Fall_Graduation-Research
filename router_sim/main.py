"""Entry point for running the educational Cisco router simulator interactively."""

from __future__ import annotations

from router_sim.cli.dispatcher import RouterCLI
from router_sim.router_core import CiscoRouter


def _default_router() -> CiscoRouter:
    iface_names = [f"GigabitEthernet0/{i}" for i in range(2)]
    return CiscoRouter(name="Router1", interfaces=iface_names)


def _repl(cli: RouterCLI) -> None:
    try:
        import readline
    except ImportError:
        readline = None

    if readline is not None:
        try:
            readline.parse_and_bind("tab: complete")
            readline.set_completer(lambda text, state: cli.complete(text, state))
            readline.set_completer_delims(" \t\n")
        except Exception:
            pass

    print("Simple router CLI. Type 'quit' to exit.")
    while True:
        hostname = cli.router.name
        if cli._mode == "user_exec":
            prompt = f"{hostname}> "
        elif cli._mode == "priv_exec":
            prompt = f"{hostname}# "
        elif cli._mode == "config":
            prompt = f"{hostname}(config)# "
        elif cli._mode in {"router_rip", "router_ospf", "router_bgp"}:
            prompt = f"{hostname}(config-router)# "
        else:
            prompt = f"{hostname}(config-if)# "
        try:
            command = input(prompt)
        except EOFError:
            print()
            break
        command = command.strip()
        if command in {"quit", "exit"} and cli._mode == "user_exec":
            break
        if command == "help":
            print(
                "Available commands:\n"
                "  show interfaces\n"
                "  show ip interface brief\n"
                "  show version\n"
                "  show running-config (privileged)\n"
                "  configure terminal\n"
            )
            continue
        output = cli.execute(command)
        if output:
            print(output)


if __name__ == "__main__":  # pragma: no cover - 手動実行用
    router = _default_router()
    cli = RouterCLI(router)
    _repl(cli)
