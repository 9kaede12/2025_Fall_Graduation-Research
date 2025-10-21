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
