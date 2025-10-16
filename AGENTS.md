# AGENTS ドキュメント

本リポジトリには、教育用レイヤ 2 スイッチを模した CLI エージェント (`switch_sim.switch.SwitchCLI`) が含まれています。ここではエージェントの振る舞いと拡張時の注意事項をまとめます。

## 実行とモード遷移

```bash
python -m switch_sim.switch
```

起動直後はユーザーモード (`Switch>`) です。

1. `enable` で特権 EXEC モード (`Switch#`) へ移行。
2. `configure terminal` でグローバル設定モード (`Switch(config)#`)。
3. `interface <name>` でインターフェース設定モード (`Switch(config-if)#`)。
4. `exit` で一段階戻り、`disable` でユーザーモードへ戻れます。

## コマンド概要

短縮形は一意であれば利用可能です（例: `sh mac`, `conf t`, `int fa0/1`）。

### ユーザーモード

- `enable`
- `show interfaces`
- `show mac address-table`
- `show interfaces status`
- `show interfaces description`
- `show interfaces switchport`
- `show interfaces trunk`
- `show vlan`
- `show vlan brief`
- `show vlan id <id>`
- `show logging`
- `show version`
- `show mac address-table dynamic`
- `show ip interface brief`
- `show clock`
- `show history`
- `show users`

### 特権モード専用

- `disable`
- `clear mac address-table`
- `show running-config`
- `show startup-config`
- `send frame <src> <dst> <port> [payload]`
- `configure terminal`

### 設定モード

- `hostname <name>`
- `enable secret <password>`
- `ip domain-lookup` / `no ip domain-lookup`
- `ip default-gateway <ip>`
- `username <user> privilege <level> secret <password>`
- `interface <name>`
- `interface range <start> - <end>`
- `interface vlan <id>`
- `line console 0`
- `line vty 0 4`
- `exit`

### インターフェース設定モード

- `description <text>`
- `shutdown` / `no shutdown`
- `switchport access vlan <id>`
- `switchport mode access`
- `exit`

### SVI 設定モード

- `ip address <address> <mask>`
- `no ip address`
- `description <text>`
- `shutdown` / `no shutdown`
- `exit`

### VLAN 設定モード

- `name <text>`
- `exit`

### ライン設定モード

- `login local`
- `no login`
- `transport input ssh`（VTY のみ）
- `exit`

## 実装メモ

- CLI は `_match_command` で短縮入力を解決し、`SwitchCLI._handle_*` 系メソッドでモード別処理を行います。
- インターフェース名は `_resolve_interface_name` が `fa0/1` のような略称を正式名称に解決します。
- `EthernetSwitch` クラスが MAC 学習、VLAN 割り当て、イベントログ等のロジックを提供します。
- VLAN インターフェースや line 設定も `EthernetSwitch` が保持し、`show running-config` をはじめ各種コマンドへ反映します。
- VLAN 自体の定義（作成・名称）やインターフェース範囲設定も保持し、短縮入力と Tab 補完に対応しています。
- `show running-config` や `show version` などは教材向けにシミュレーションされた出力を返します。
- 実機で存在するが未実装のコマンド（例: `show arp`, `show spanning-tree`）は識別したうえで未対応メッセージを返します。
- `readline`（libedit 含む）を利用して Tab 補完を提供し、曖昧時は候補語を一覧表示します。環境が補完に非対応の場合は自動的にフォールバックします。

## 拡張時のガイド

1. 新コマンドを追加する場合は、該当モードの `_handle_*` にエントリを追加し、`README.md` と本ファイルを更新してください。
2. 短縮入力を許可したい場合は `_match_command` を利用し、必要に応じて `allow_suffix` を指定します。
3. 新しい show 系機能を実装する際は、`EthernetSwitch` に専用メソッドを追加し、`SwitchCLI._handle_show_commands` で呼び出す構成を守ります。
4. インターフェース関連機能を拡張する場合は、ポート解決ロジックの互換性を維持してください。

以上を守ることで、学習用途に適した一貫性のある CLI 振る舞いが保てます。
