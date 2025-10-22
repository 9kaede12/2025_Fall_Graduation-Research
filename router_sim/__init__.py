# Cisco ルーターシミュレーション用パッケージ
#
# 主要機能は router_sim.router モジュールで提供されます。

from .router import RouterCLI, CiscoRouter

__all__ = ["RouterCLI", "CiscoRouter"]

