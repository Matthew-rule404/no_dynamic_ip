# no_dynamic_ip
Use Static IPv4 / IPv6 addresses with netplan. Set route information from DHCP server.

## English

### Development Environment
- Developed for Ubuntu 24.04 LTS
- Uses `noble`
- Expected to work in any netplan environment, including Debian/Armbian with Bookworm

### Dependencies
- `yq` version v4.44.3 for parsing YAML configuration files
- `ipcalc` for IP address calculations
- `iproute2` for IP-related operations

### Project Intent
Utilize fixed IPv4/IPv6 addresses while obtaining route information from a DHCP server.

### Implemented Features
1. Fixed IPv4 addresses using YAML configuration files in `/etc/netplan`.
2. Fixed IPv6 addresses using YAML configuration files in `/etc/netplan`.
3. Remove unnecessary dynamic addresses when using fixed IPv4/IPv6 addresses with netplan.
4. Re-add route information tied to dynamic addresses as fixed address routes.
   - IPv4: Add default route as proto kernel instead of proto dhcp.
   - IPv6: Default route using link-local addresses is not removed; global route information is untested.
5. Locale detection implemented (supports Japanese and English).
6. Execution confirmation when run standalone.
7. Dry-run mode.
8. Debug mode.
9. Log collection.

### How to Run
```sh
chmod +x no_dynamic‗ip.sh
```

### Execution Arguments
-D|--debug [x]: Debug mode; add x for line mode
-S|--silent: Silent mode
-DRY|--dry-run: Dry-run mode

### Future Plans
Save information obtained from DHCP servers
DNS server information and retain settings when removing dynamic addresses
SIP server information and retain settings when removing dynamic addresses
Log rotation

## 日本語
### 開発環境
Ubuntu 24.04 LTSを対象に開発しています。
nobleを利用
netplanを利用する環境であれば同じものが動くと想定されます。※debian/armbian環境のbookwormで利用する予定

### 依存関係
YAML設定ファイルの内容を解析するために yq バージョンv4.44.3を利用
IPアドレス関連の計算に ipcalc
IP関連の操作に iproute2
プロジェクトの意図
固定IPv4/IPv6アドレスを利用しつつ、DHCPサーバーから情報を取得した経路情報などを利用したい。

### 現在のバージョンで実現・実装済みの機能
1. /etc/netplan 配下のYAML形式の設定ファイルで固定IPv4アドレスを利用可能に。
2. /etc/netplan 配下のYAML形式の設定ファイルで固定IPv6アドレスを利用可能に。
3. netplanで固定IPv4/IPv6アドレスを利用する場合に、自動的にDynamicアドレスが付与されるため、必要のないDynamicアドレスを削除する。
4. Dynamicアドレスを削除すると、そのアドレスに紐づく経路情報が削除されるため、Dynamicアドレスを削除する間に解析し、その経路情報を固定アドレスで利用可能な経路情報として再追加。
   IPv4: ダイナミックアドレスと関連して削除されるデフォルト経路をproto dhcpからproto kernelで利用できるように追加
   IPv6: リンクローカルアドレスを利用したデフォルト経路の場合削除されない。グローバル用の経路情報が付与される場合については環境が整っていないため動作未検証
5. ロケール判定を実装（日本語/英語両対応）
6. 単体実行時に実行確認機能
7. ドライランモード実装
8. デバッグモード実装
9. ログ取得機能実装

### 実行方法
```sh
chmod +x no_dynamic‗ip.sh
```
### 実行時の引数
 -D|--debug [x]: デバッグモード。xを付けるとラインモードを利用可能
 -S|--silent: サイレントモード
 -DRY|--dry-run: ドライランモード

### 今後の予定
DHCPサーバーから取得できる各情報を保存する機能
DNSサーバー情報の確認とダイナミックアドレス削除時の設定値保持
SIPサーバー情報の確認とダイナミックアドレス削除時の設定値保持
ログローテート機能

