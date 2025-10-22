# 2025_Fall_Graduation-Research

## Switch simulation (Python)

The repository now contains a minimal Ethernet switch simulator that can be used
to practice foundational concepts such as MAC アドレス学習、VLAN 設定、ポートの有効/無効化、基本的な show コマンドの確認など。

### 実行方法

```bash
python -m switch_sim.switch
```

起動すると Cisco IOS 風の CLI が立ち上がります。以下のようなコマンドが利用できます。

- `enable` – ユーザーモードから特権 EXEC モードへ移行
- `disable` – 特権 EXEC モードからユーザーモードへ戻る
- `show mac address-table` – 学習済み MAC アドレスの表示
- `show mac address-table dynamic` – 動的エントリのみ表示（シミュレーションでは同じ内容）
- `show interfaces` – 各ポートの詳細情報を表示
- `show interfaces status` – 各ポートのステータス確認
- `show interfaces description` – ポート説明の一覧を表示
- `show interfaces switchport` – 各ポートのスイッチポート設定を表示
- `show interfaces trunk` – トランクポートの有無を確認（本シミュレータでは未設定）
- `show vlan` – VLAN ごとのポート割り当てを確認
- `show vlan brief` – VLAN 一覧を簡易表示
- `show vlan id <id>` – 指定 VLAN の詳細を表示
- `show version` – シミュレータのソフトウェア情報を表示
- `show ip interface brief` – ポートの概要を一覧表示
- `show running-config` – 現在の設定を表示
- `show startup-config` – 保存済み設定（シミュレータでは簡易表示）を確認
- `show clock` – 現在時刻を表示
- `show history` – 直近のコマンド履歴を表示
- `show users` – 接続ユーザー情報を表示
- `show spanning-tree` – STP の状態を確認
- `hostname <name>` – ホスト名を変更（グローバル設定モード）
- `enable secret <password>` – 特権 EXEC パスワードを設定
- `ip domain-lookup` / `no ip domain-lookup` – DNS ルックアップの有効/無効を切り替え
- `ip default-gateway <ip>` – デフォルトゲートウェイを設定
- `username <user> privilege <level> secret <password>` – ローカルユーザーを作成
- `spanning-tree mode rapid-pvst` – STP モードを設定
- `spanning-tree vlan <id> priority <value>` – VLAN の STP プライオリティを調整
- `clear mac address-table` – 学習済み MAC アドレスのクリア
- `send frame <src> <dst> <port>` – 指定ポートにフレームを注入して学習挙動を確認
- `configure terminal` → `interface <name>` – インターフェース設定モードへ移行
- `interface range <start> - <end>` – ポートの範囲をまとめて設定
- `vlan <id>` → `name <text>` – VLAN を作成し名称を設定
- `interface vlan <id>` → `ip address <addr> <mask>` → `no shutdown` – 管理用 VLAN インターフェースを設定
- `switchport access vlan <id>` – VLAN の変更
- `switchport mode access` – インターフェースをアクセスモードに設定
- `spanning-tree portfast` / `no spanning-tree portfast` – ポートファストの有効/無効を切り替え
- `shutdown` / `no shutdown` – ポートの管理状態変更
- `description <text>` – ポートの説明設定
- `line console 0` → `login local` – コンソール認証をローカルユーザーへ切り替え
- `line vty 0 4` → `transport input ssh` / `login local` – リモートアクセス設定
 - `show spanning-tree` – STP の状態を確認

CLI は `Switch>` プロンプト（ユーザーモード）で起動し、`enable` 実行後は `Switch#`（特権モード）に切り替わります。`disable` で再びユーザーモードへ戻れます。

各コマンドは一意に識別できる短縮形でも実行できます（例: `sh mac`、`conf t`、`int fa0/1`）。

一部コマンド（例: `show running-config`, `show startup-config`, `clear mac address-table`, `send frame`, `configure terminal`）は特権 EXEC モードでのみ利用できます。

`show arp` や `show ip route` など実機に存在する一部コマンドは入力可能ですが、シミュレータでは「対応していない」旨のメッセージを返します。

Tab キーで Cisco 風のコマンド補完が利用でき、曖昧な場合は候補語を表示します。

`help` コマンドで使用可能なコマンド一覧を確認できます。

## Router simulation (Python)

ルーターシミュレータは Cisco IOS 風の CLI で基本的なインターフェース運用を学習できます。

```bash
python -m router_sim.router
```

### 主なコマンド

- `enable` / `disable` – ユーザー/特権モードの切り替え
- `configure terminal` – グローバル設定モードへ移行
- `hostname <name>` – ルーター名を変更
- `enable secret <password>` – 特権パスワードを設定
- `service password-encryption` / `no service password-encryption` – パスワード表示の暗号化を制御
- `service timestamps log datetime` / `no service timestamps log datetime` – ログ時刻の有効化/無効化
- `ip domain-lookup` / `no ip domain-lookup` – DNS ルックアップ設定
- `ip name-server <ip> [ip...]` / `no ip name-server [ip...]` – DNS サーバーを設定/削除
- `banner motd #...#` – ログイン時バナーを設定
- `clock timezone <zone> <offset>` – タイムゾーンを設定
- `router rip` → `network <addr>` / `version <1|2>` / `no auto-summary` / `redistribute static` – RIP を設定
- `router ospf <process-id>` → `router-id <ip>` / `network <ip> <wildcard> area <id>` / `redistribute static` – OSPF を設定
- `router bgp <asn>` → `neighbor <ip> remote-as <asn>` / `network <ip> mask <mask>` / `redistribute static` – BGP を設定
- `ip nat inside` / `ip nat outside` – インターフェースの NAT 役割を設定
- `ip nat pool <name> <start> <end> netmask <mask>` / `no ip nat pool <name>` – NAT プールを設定
- `ip nat inside source list <list> pool <name> [overload]` / `no ip nat inside source list <list> pool <name>` – NAT マッピングを設定
- `ip route <dest> <mask> <next-hop>` / `no ip route <dest> <mask> <next-hop>` – 静的ルートの追加/削除
- `interface <name>` – インターフェース設定モード (`GigabitEthernet0/0` などに対応)
- `ip address <address> <mask>` / `no ip address` – IP アドレスの設定/削除
- `shutdown` / `no shutdown` – インターフェースの無効化/有効化
- `description <text>` – インターフェース説明の設定
- `show interfaces` – 詳細なインターフェース情報
- `show ip interface brief` – インターフェース概要
- `show running-config` – 現在の設定
- `show version` – ソフトウェア情報
- `show startup-config` – 起動時設定（シミュレーションでは簡易表示）
- `show processes` – 擬似プロセス情報
- `show users` – 接続ユーザーの一覧
- `show arp` – ARP テーブルを表示
- `show ip route` – ルーティングテーブル（静的/RIP/OSPF/BGP を反映）
- `show ip protocols` – 動作中のルーティングプロトコルを表示
- `show ip ospf neighbor` / `show ip ospf database` – OSPF の状態を確認
- `show ip bgp` – BGP ルーティングテーブルを確認
- `show ip nat translations` – NAT プール/マッピングの概要を表示
- `copy running-config startup-config` / `write memory` – 設定を保存（疑似動作）
- `reload` – ルーターの再起動をシミュレート
- `clear arp-cache` – 動的 ARP 項目をクリア
- `ping <ip>` / `traceroute <ip>` – ICMP 疎通確認・経路確認を実行

インターフェースには仮想 MAC アドレスが割り当てられ、管理状態と IP 情報が保持されます。短縮コマンドや Tab 補完にも対応しています。
