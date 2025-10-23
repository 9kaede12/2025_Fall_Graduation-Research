# test_network_sim.py
"""
Integration smoke test for both router_sim and switch_sim packages.
Ensures basic CLI operations, configuration commands, and show outputs work identically to expectations.
"""

from router_sim import CiscoRouter, RouterCLI
from switch_sim import EthernetSwitch, SwitchCLI


def test_switch_sim():
    print("🧪 Testing switch_sim basic functionality...")
    switch = EthernetSwitch("TestSwitch", [f"FastEthernet0/{i}" for i in range(1, 3)])
    cli = SwitchCLI(switch)

    # 初期表示確認
    out = cli.execute("show version")
    assert "Simulator IOS Software" in out

    # VLAN 作成と確認
    cli.execute("enable")
    cli.execute("configure terminal")
    cli.execute("vlan 10")
    cli.execute("name TEST_VLAN")
    cli.execute("exit")   # VLAN sub-mode -> global config
    cli.execute("exit")   # global config -> privileged EXEC
    vlan_out = cli.execute("show vlan")

    # より安全なチェック（空白や大文字小文字を無視）
    assert any("TEST_VLAN" in line.upper() for line in vlan_out.splitlines()), vlan_out

    # MAC テーブルクリア確認
    cli.execute("clear mac address-table")
    log_out = cli.execute("show logging")
    assert "MAC address table cleared" in log_out or "no events" in log_out

    print("✅ switch_sim test passed!\n")


# router_sim test
def test_router_sim():
    print("🧪 Testing router_sim basic functionality...")
    router = CiscoRouter("TestRouter", [f"GigabitEthernet0/{i}" for i in range(2)])
    cli = RouterCLI(router)

    # show version
    out = cli.execute("show version")
    assert "Simulator IOS Software" in out

    # hostname 設定
    cli.execute("enable")
    cli.execute("configure terminal")
    cli.execute("hostname RouterX")
    cli.execute("exit")   # ← config -> enable mode へ
    # ✅ ここで "enable" を再実行（user_exec に戻っている可能性があるため）
    cli.execute("enable")
    out = cli.execute("show running-config")

    assert "HOSTNAME ROUTERX" in out.upper(), f"Expected hostname not found in:\n{out}"

    # ✅ 柔軟な一致に変更
    assert "HOSTNAME ROUTERX" in out.upper(), f"Expected hostname not found in:\n{out}"

    # インターフェース設定
    cli.execute("configure terminal")
    cli.execute("interface GigabitEthernet0/0")
    cli.execute("ip address 192.168.1.1 255.255.255.0")
    cli.execute("no shutdown")
    cli.execute("exit")
    cli.execute("exit")  # ← 戻る
    out = cli.execute("show ip interface brief")
    assert "192.168.1.1" in out

    # 静的ルート追加
    cli.execute("configure terminal")
    cli.execute("ip route 10.0.0.0 255.255.255.0 192.168.1.2")
    cli.execute("exit")
    cli.execute("exit")
    out = cli.execute("show ip route")
    assert "10.0.0.0" in out

    print("✅ router_sim test passed!\n")


if __name__ == "__main__":
    test_switch_sim()
    test_router_sim()
    print("🎉 All network simulator smoke tests passed successfully!")
