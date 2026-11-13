# NPS

一款轻量级、高性能、功能强大的内网穿透软件。

# 特性

- 协议支持全面，兼容几乎所有常用协议
- Web 管理界面，方便配置和监控
- 客户端无需配置，直接运行即可使用
- 支持 TCP、UDP、HTTP、HTTPS 等多种协议
- 支持端口映射、域名解析、反向代理等功能

# 快速开始

## 服务端部署

### Linux/Mac

```bash
# 启动
sudo ./nps install
sudo nps start

# 或者直接运行
./nps
```

### Windows

```powershell
# 启动
nps.exe install
nps.exe start

# 或者直接运行
nps.exe
```

## 客户端部署

```bash
# 直接运行（推荐）
./npc -server=你的服务器地址:8024 -vkey=你的vkey

# 安装系统服务
./npc install -server=你的服务器地址:8024 -vkey=你的vkey
```

### Windows 客户端

```
双击 npc.exe，按照提示输入服务器地址和 vkey 即可完成配置。
```

## Web GUI 客户端 (npc_gui)

桌面版客户端自带本地 Web 管理面板，静态页面已通过 `go:embed` 打包进二进制，单文件即可运行。

```bash
./npc_gui                      # 默认监听 127.0.0.1:9666，自动打开浏览器
./npc_gui -port 12345          # 指定端口（立即生效）
./npc_gui -no-open -no-tray    # 无头/测试环境：不弹浏览器、不显示状态栏

# 也支持像命令行客户端一样带参数运行（连接参数名与 npc 一致）
./npc_gui -server=你的服务器:8024 -vkey=你的vkey
./npc_gui -config=/path/to/npc.conf          # 复用命令行版 npc.conf 的 [common] 段
./npc_gui -headless -server=你的服务器:8024 -vkey=你的vkey   # 完全无界面，只跑隧道
./npc_gui -server=你的服务器:8024 -vkey=你的vkey -save        # 参数落盘，之后双击即用
./npc_gui -version                          # 显示版本
./npc_gui -print-config                     # 打印生效配置（vkey 打码）
```

**连接参数**：`-server`、`-vkey`、`-type`（tcp|kcp）、`-tls_enable`、`-proxy`、
`-disconnect_timeout`、`-config`。另外还支持环境变量 `NPC_SERVER_ADDR`、
`NPC_SERVER_VKEY`（与命令行版 npc 同名）、`NPC_CONN_TYPE`、`NPC_TLS_ENABLE`、
`NPC_PROXY_URL`、`NPC_DISCONNECT_TIMEOUT`。

**运行模式**：`-headless`（无界面，等价于命令行客户端，支持逗号分隔多个 vkey 并发重连）、
`-autostart`（面板照常启动但自动连接）、`-save`（把生效参数写入用户配置）、
`-port` / `-no-open` / `-no-tray`；观测类 `-version`、`-print-config`、
`-log`（store|stdout|file|both）、`-log_level`、`-log_path`、`-pprof`。
完整列表见 `./npc_gui -h`。

配置优先级（低 → 高，逐字段覆盖）：

```
编译期预置 (-ldflags -X) < 已保存的 GUI 配置 < -config 文件 < NPC_* 环境变量 < 命令行参数
```

- 显式传了 `-server` / `-vkey` / `-config` 时会自动连接，不必再进面板点「启动」；
  仅靠编译期预置或已保存配置启动时仍保持手动启动，需要自动连请加 `-autostart`。
- `-config` 既接受 `npc_gui.json` 格式，也接受命令行版 `npc.conf`；后者**只读取 `[common]` 段**
  的连接参数，`[tcp]` / `[web]` / `[secret]` 等本地映射段不生效（隧道由服务端下发，不是客户端本地定义）。
  面板模式只连接第一个 vkey，多 vkey 请用 `-headless`。
- `-headless` 不启动 Web 面板、状态栏、浏览器，日志默认走 stdout；Ctrl+C 优雅退出。
  服务模式（`-service-run`）优先于 `-headless`。
- 开机自启项只写入 `-service-run`，**不会继承启动时的 `-server` 等参数**。想让服务使用固定连接参数，
  先 `-save` 落盘（或在编译时预置）再安装服务。
- `-print-config` 的 vkey 始终打码；`-save` 才会把 vkey 写入本机用户配置文件。

**编译期预置连接参数（定制发行包）**：`build.assets.sh` 的 7 个 `npc_gui_*` 包可由环境变量注入默认值，
用户拿到后打开面板就已填好服务器地址（也可直接 `-autostart` / `-headless` 运行）：

```bash
NPC_GUI_SERVER=你的服务器:8024 \
NPC_GUI_VKEY=你的vkey \
NPC_GUI_LABEL="某某专用" \
./build.assets.sh
```

可注入项：`NPC_GUI_SERVER`、`NPC_GUI_VKEY`、`NPC_GUI_TYPE`、`NPC_GUI_TLS`、
`NPC_GUI_PROXY`、`NPC_GUI_DISCONNECT_TIMEOUT`、`NPC_GUI_LABEL`。
不设置时 7 个包仍是「自己填配置」的通用客户端，行为与之前完全一致；
真实地址/密钥不要写进仓库，本地用环境变量、CI 里用 Secret 传入，
构建后用 `./npc_gui -version` / `-print-config` 核对。
Release workflow（`pkg.yml`）的 Build 步骤已接好同名变量：密钥读仓库 Secrets
（`NPC_GUI_VKEY`），其余读仓库 Variables，都留空即构建通用包。

- **端口策略**：默认 `9666`，可在面板「本地管理面板 → 面板端口」里修改（重启后生效）。
  若首选端口被占用，会自动改用随机可用端口；本次实际地址写入
  `<用户配置目录>/npc/npc_gui.port`（macOS 为 `~/Library/Application Support/npc/`，
  Linux 为 `~/.config/npc/`，Windows 为 `%AppData%\npc\`），面板与状态栏都会显示真实端口。
- **开机提醒与状态栏**：安装为登录自启项后，开机时发一次系统通知，并在
  macOS 菜单栏 / Windows 系统托盘常驻显示 `NPC :端口`，**点击图标即可打开面板**。
  Linux 无原生托盘时降级为系统通知 + 面板内显示端口。
- **服务安装**：在面板里点「安装服务」即可，默认安装为当前用户的登录自启项
  （macOS 为 `~/Library/LaunchAgents/npc-gui.plist`），不需要管理员密码；
  服务进程同样拉起面板和状态栏，不再是只有隧道、找不到管理地址的后台进程。

## 邮箱验证码登录与账号权限

### 接入中心邮件服务

发信不再走本地 SMTP：本项目不保存任何 SMTP 主机、账号或授权码，统一通过
`https://t.jaxiu.cn/api/mail/v1` 的中心邮件服务投递——先用 OAuth2
`client_credentials` 换取 `access_token`（进程内缓存、过期自动刷新），再以
`Authorization: Bearer` 调 `POST /send`。**租户凭据只从服务进程环境变量读取，
`conf/nps.conf` 与仓库里不写任何密钥。**

| 环境变量 | 必填 | 说明 |
| --- | --- | --- |
| `NPS_MAIL_CLIENT_ID` | 是 | 在 `/mail-service` 管理页「注册新业务」拿到的 client_id |
| `NPS_MAIL_CLIENT_SECRET` | 是 | 同一次注册返回的 client_secret（只显示一次，丢失需轮换） |
| `NPS_MAIL_FROM` | 否 | 默认 `devtools@jaxiu.cn`（中心服务自身发件人，已登记在 nps 业务白名单内）。改用其它地址时**必须**同步加进该业务的发件人白名单（精确地址、`@domain` 后缀或 `*`），否则返回 403 `from_not_allowed` |
| `NPS_MAIL_BASE_URL` | 否 | 默认 `https://t.jaxiu.cn/api/mail/v1` |
| `NPS_MAIL_SUBJECT_PREFIX` | 否 | 默认 `[NPS] ` |

示意（生产已有同名容器时，请按实际 tag / 容器名调整，或改用现有部署脚本）：

```bash
docker run -d --net=host --restart=always -v /root/docker/nps/conf:/conf \
  -e NPS_MAIL_CLIENT_ID='<client_id>' \
  -e NPS_MAIL_CLIENT_SECRET='<client_secret>' \
  --name new_nps_axiu_plus axiu/nps:<tag> -conf_path=/
```

不想让密钥出现在 `docker inspect` 里时，可把 client_secret 写进一个 0600 文件，
改用 `NPS_MAIL_CLIENT_SECRET_FILE=/run/secrets/nps_mail_client_secret` 指向它。
中心服务在请求不带 `from` 时也会填自己的默认发件人，但**白名单为空时连默认发件人一起拒绝**，
所以 nps 客户端始终显式发送 `from`（默认 `devtools@jaxiu.cn`）。

验证码相关参数仍在 `conf/nps.conf`：`email_login_enable`、`email_code_ttl_minutes`、
`email_code_resend_seconds`、`email_code_max_attempts`、`email_code_ip_limit`。
两个必填环境变量未齐备时，登录页自动退回纯密码登录，不影响原有功能。

### 绑定与使用

1. 超级管理员在「用户与权限」新建/编辑用户时可直接填写邮箱；用户也可登录后到「账号与安全」自助绑定。
2. 自助绑定需向该邮箱发送验证码并完成校验，一个邮箱只能绑定一个账号（大小写不敏感）。
3. 登录页切换「邮箱验证码」标签，获取验证码后即可免密登录；验证码一次性、限时、按用途（登录 / 绑定）隔离。

### 普通用户自助客户端

- 普通用户可在「客户端」页面自行新增客户端，创建后**自动写入 `conf/users.json` 归属本人**，无需超级管理员再分配。
- 普通用户只能查看、编辑、启停、删除自己的客户端及其隧道、域名解析；越权请求在服务端被拦截（不会因前端隐藏按钮而失效）。
- 流量 / 速率 / 连接数 / 隧道数上限以及旧版 Web 登录凭据仍由超级管理员设置；用户级端口范围继续受全局 `allow_ports` 与自身 `AllowPorts` 双重约束。
- 没有任何客户端的普通用户不会看到任何客户端（旧版空归属范围导致的越权查看已修复）。

## Docker 部署

### 服务端

```bash
# 拉取镜像
docker pull axfinn/nps

# 运行容器
docker run -d --name nps \
  -v /etc/nps:/conf \
  -p 8024:8024 -p 8080:8080 -p 8443:8443 \
  axfinn/nps
```

### 客户端

```bash
# 拉取镜像
docker pull axfinn/npc

# 运行容器
docker run -d --name npc \
  axfinn/npc -server=你的服务器地址:8024 -vkey=你的vkey
```

# 配置说明

默认配置文件位于 `conf/nps.conf`，主要配置项：

| 配置项 | 说明 |
|--------|------|
| http_port | HTTP 端口 |
| https_port | HTTPS 端口 |
| bridge_port | 客户端连接端口 |
| vkey | 认证密钥 |

# 更新日志

- 2026-11-13 v0.26.84
  变更：
  - **发信统一接入中心邮件服务** `t.jaxiu.cn/api/mail/v1`：移除本地 SMTP 全套实现与 `smtp_*` 配置，
    改走 OAuth2 `client_credentials` 换 token（进程内缓存、过期自动刷新）+ `POST /send`；
    租户凭据只从环境变量注入（必填 `NPS_MAIL_CLIENT_ID` / `NPS_MAIL_CLIENT_SECRET`），
    仓库与 `conf/nps.conf` 不再保存任何发信密钥。默认发件人 `devtools@jaxiu.cn`，
    必须登记在该业务的发件人白名单内。
  - 单测改为假中心服务，覆盖 Basic 认证、Bearer、token 复用、401 刷新重试、403 错误透传、
    默认发件人与主题注入防护。

- 2026-11-12 v0.26.81
  新增：
  - **npc_gui 支持命令行参数运行**：与命令行版 `npc` 同名的 `-server/-vkey/-type/-tls_enable/-proxy/-disconnect_timeout/-config`，
    外加 `-headless`（完全无界面跑隧道、支持逗号分隔多 vkey）、`-autostart`、`-save`、`-version`、`-print-config`、`-log*`；
    支持 `NPC_*` 环境变量与四级配置优先级，显式传连接参数时自动连接，纯 GUI 启动行为不变。
  - **编译期预置连接参数**：`build.assets.sh` 的 7 个 `npc_gui_*` 包可用 `NPC_GUI_*` 环境变量经 `-ldflags -X` 注入默认值，
    不注入时行为不变；真实地址/密钥不写进仓库。脚本补上 `#!/usr/bin/env bash`（用到 bash 专有语法）。
  修复：
  - npc_gui 服务模式判定不再依赖 `!service.Interactive()` 猜测，避免无 tty / systemd 环境下把 `-headless` 误判成服务模式。
  注意：
  - 本次改动集中在 Web GUI 客户端，服务端逻辑未变；`docker.yml` 仍按惯例产出 `axiu/nps:v0.26.81` 镜像。
  - 7 个 `npc_gui_*` 发行包由 Release workflow（`pkg.yml`）产出，推 tag 不会触发它；
    需在 GitHub 上以 `v0.26.81` 创建 Release，或手动运行该 workflow 并选择这个 tag。

- 2026-11-12 v0.26.80
  新增：
  - **Web GUI 客户端 (npc_gui) 正式随发行包发布**：`build.assets.sh` 补齐 7 个平台构建、`pkg.yml` 补齐上传项，下载页列出的图形界面客户端不再缺包。构建改为整包 `go build ./gui/npc`，保证 `go:embed` 静态页面被打进二进制。
  - npc_gui 本地面板端口策略：默认 `9666`，优先级 `-port` > 配置 `web_port` > `9666`；被占用时自动随机回退并复用已绑定 listener，实际地址写入 `<用户配置目录>/npc/npc_gui.port`，`/api/status`、`/api/port` 可查改。
  - npc_gui 状态栏常驻：macOS 菜单栏 / Windows 系统托盘显示 `NPC :端口`，点击图标打开面板，开机自启发一次通知；纯系统脚本引擎实现，不引入 cgo，保持 `CGO_ENABLED=0` 多平台交叉编译。端口文件同时作为心跳，主进程退出后托盘自行消失。
  - 新建隧道页展示**当前用户的专属端口范围**，端口留空时默认取段内最小空闲端口并在输入框预填；前端校验超范围端口，后端 `TestServerPort` 继续兜底。
  修复：
  - npc_gui 服务安装：服务模式现在同样启动 Web 面板与状态栏（此前只有隧道、找不到管理地址）；改用 `-service-run` 显式识别服务进程；macOS 改为用户级 LaunchAgent + 自定义模板，修掉 kardianos 默认日志目录不可写、双击运行时提权失败、首次保存配置目录不存在等导致安装必失败的问题。
  - 命令行版 `npc install` 现在把服务 `ExecStart` 指向安装后的二进制，而非用户临时运行路径，避免重启或原文件移动后服务失效；修复 `nps` 中 `logPath` 被 `:=` 遮蔽导致配置不生效。
  - `.gitignore` 里的 `npc` / `nps` 锚定为 `/npc` `/nps`：此前会匹配 `gui/npc/`、`cmd/nps/` 目录，导致新增源码被静默忽略、发版漏文件。
  注意：
  - 有专属端口段的普通用户，新建隧道且端口留空时改为**优先使用自己段内最小空闲端口**（段满才回退共享池），与 v0.26.79 的「共享池优先」语义不同；超管与无专属段用户行为不变，老隧道不受影响。

- 2026-11-12 v0.26.79
  新增：
  - 共享池随机端口支持**一键转为固定端口**：列表页图钉按钮、新建页/编辑页勾选框，或 `POST /index/pinport`（`action=pin|unpin`）。
  - 固定后端口**永不过期**：停用、客户端离线、编辑保存、服务重启都不再归还也不换号；分配器把该端口永久排除，其他隧道不会随机拿到。用户管理页新增「已固定端口」统计，列表页显示「共享 / 固定」标签。
  - 固化状态只写 `tasks.json` 的 `PortPool="fixed"`，不新增状态文件、重启自动对账，也不占用用户 100 个专属端口配额；解除固定可恢复临时语义。
  优化：
  - 固化/解除带归属校验（普通用户只能操作自己的客户端），已固定端口在编辑与重启时由服务端按归属放行，避免他人借用。
  - **升级兼容性加固**：`tasks.json` 里没有 `PortPool` 字段的老隧道一律视为传统固定端口，分配器把其端口（含停用状态）永久排除，杜绝「停用的老隧道端口恰好落在池段内被新隧道抢走」；启动/停用/重启/编辑均不换端口、不回收。端口池只影响新建且端口留空的隧道。

- 2026-11-12 v0.26.78
  新增：
  - 新增端口池：40000-49999 按每块 100 个端口自动分配给新建普通用户（写入 `User.AllowPorts`，专属固定）；50000-60000 作为共享池，建隧道端口留空即随机分配。
  - 共享池端口在停用 / 删除隧道 / 客户端离线时自动归还，停用后再次启动会重新取新端口；共享池耗尽自动回退用户专属块。
  - 共享段禁止手工指定（Web 表单与 npc 配置均校验）；分配排除系统监听端口与运行中隧道端口，并用在途租约 + 互斥锁避免并发重复分配。
  - 端口池不新增状态文件，专属块与共享租约分别落在 `users.json` / `tasks.json`，重启自动对账；不改动全局 `allow_ports`，老隧道不受影响，且全局白名单仍是共享池的硬上限；`port_pool_enable=false` 可一键回退。
  修复：
  - 修复 `layout.html` / 注册页中 `window.nps` 赋值在 `web_base_url` 为空时渲染成非法 JS，导致整段内联脚本（含注册按钮函数）失效；并把 `layout.html` 中被挤到 `</html>` 之后的脚本移回 `<body>` 内。
  优化：
  - 全局 `allow_ports` 缓存改为读写锁保护，修复 reload 时的并发数据竞争。
  - 新建 / 复制隧道失败时回滚半成品任务；编辑页与停用接口补齐失败分支的 `return`，避免错误响应后继续执行。

- 2026-11-12 v0.26.77
  修复：
  - 修复「获取验证码」等按钮点击无反应 / 报函数未定义：登录页与「账号与安全」页存在元素 `id` 与全局函数同名（如 `id="sendLoginCode"` 与 `function sendLoginCode()`），内联 `onclick` 作用域链会优先命中 form 内的同名元素而非全局函数。已重命名按钮与 Tab 的 `id`，并将内联事件改为显式 `window.xxx()` 调用；同时移除未被引用且可能破坏脚本的 `window.nps` 赋值。

- 2026-11-12 v0.26.76
  修复：
  - 修复登录页模板残留的重复 `</body></html>`，导致内联脚本位于 `</html>` 之后、部分浏览器下「获取验证码」等按钮报前端函数未定义的问题；脚本已移回 `<body>` 内。

- 2026-11-12 v0.26.75
  新增：
  - 支持用户邮箱绑定与邮箱验证码登录：发信统一接入 `t.jaxiu.cn` 中心邮件服务（OAuth2 client_credentials + `/send`），本地不再保存 SMTP 配置，租户凭据只走环境变量；验证码限时、一次性、按用途隔离，并带邮箱 / IP 双重限流。
  - 新增「账号与安全」自助页面，用户可自行通过邮箱验证码绑定 / 解绑邮箱；超管可在用户管理中直接设置。
  - 普通用户可自助新增客户端并自动归属本人；同时收紧越权校验，无客户端的普通用户不再被当作「可见全部客户端」。
  - 普通用户可编辑 / 启停 / 删除自己的客户端，但配额与旧版 Web 凭据仍仅超管可改；修复旧版图片验证码校验失败后仍继续尝试登录的问题。

- 2026-11-11 v0.26.74
  优化：
  - 修复 GitHub Actions Docker 多架构镜像构建过慢 / 偶发失败（超时）的问题：构建阶段改用 BUILDPLATFORM 交叉编译规避 QEMU 模拟、GOPROXY 改为走模块代理、接入 buildx GitHub 缓存（type=gha）并显式设置超时。

- 2026-11-11 v0.26.73
  新增：
  - 引入独立用户体系：新增超管（super_admin）与普通用户（user）两种角色，独立存储于 conf/users.json。
  - 普通用户仅可查看与操作自身归属的客户端与隧道；用户管理、全局设置仅超管可访问。
  - 隧道监听端口支持按用户划分可用范围（AllowPorts）：超管仅受全局 allow_ports 约束，普通用户受自身端口段与全局白名单的交集约束。
  - 修复 nps reload 不刷新全局 allow_ports 的问题（现会重新加载）。
  - 用户密码采用加盐迭代 SHA-256 存储，首次启动自动从 nps.conf 与客户端 Web 账号迁移兼容。

- 2025-11-05 v0.26.27
  新增：
  - 1.客户端新增【IP白名单】，可通过两种方式添加IP:
    - 方式1：在【客户端】新建/修改页面，配置IP授权密码，不在IP白名单的外网访问将被跳转到 IP 授权页面，输入正确的授权密码，即可完成添加 IP。
    - 方式2：在【客户端】新建/修改页面，直接添加IP到白名单中。
  - 2.客户端配置移除【压缩】和【加密】功能，此功能会显著提高内存和CPU占用率，"利大于弊"。
  - 3.客户端默认不再提供配置文件，强烈推荐使用无配置文件模式启动客户端


- 2025-08-15  v0.26.26
  修复：
  - windows注册服务 使用tls无法连接
  - 域名解析自动HTTPS逻辑bug


- 2025-05-28  v0.26.25
  新增：
  - nps增加`nps(.exe) -server` 命令，用于管理NPS服务，安装和卸载服务在 Linux 下需要有 sudo 权限，Windows 下需要有管理员权限。
  - 增加【TLS快捷启动命令】，可用于在tls模式下，快速启动客户端。


- 2025-04-16  v0.26.24
  新增：
  - 隧道支持复制功能，在隧道页面增加复制按钮，除了端口号为随机生成外，其他参数全部拷贝。

  修复：
  - 私密代理连接时服务端会报错退出



- 2025-04-11  v0.26.23
  新增：
  - TCP 隧道支持 Proxy Protocol 协议来传递经过请求的真实 IP。

  修复：
  - 客户端较多时，协程增长过快


- 2025-01-23  v0.26.22
  优化：
  - 客户端注册系统服务时，将按照 `npc-[vkey].log` 格式保存日志，每个客户端VKEY单独一个日志文件
  - 域名模式，HTTPS证书支持上传文件和文件路径，系统将自动识别路径还是证书内容

  修复：
  - ipv6地址显示不全


- 2025-01-07  v0.26.21
  新增：
  - 客户端列表页面新增【快捷启动命令】，此命令为连接地址+链接秘钥的base64编码，方便一键启动、一键安装客户端
  - 域名解析和隧道列表增加访问地址，可以点击隧道链接，直接网页打开

  优化：
  - 修改vkey生成方式，由16位缩短至10位，截取uuid前10位，避免重复
  - 优化客户端启动方式，当npc文件目录下无配置文件时，可直接双击运行客户端，输入命令完成启动、安装、卸载客户端

  注意：强烈推荐使用无配置文件模式启动客户端，所有数据应该在服务端保存和配置，而客户端只做连接转发。

- 2024-11-07  v0.26.20
  新增：
  - 客户端增加创建时间

  修复：
  - 客户端限速单位不统一
  - 隧道数量限制无法统计域名映射

- 2024-06-01  v0.26.19
  - golang 版本升级到 1.22
  - 增加自动https，自动将http 重定向（301）到 https
  - 客户端命令行方式启动支持多个隧道ID，使用逗号拼接
  - 移除 nps.conf 参数 `https_just_proxy`, 调整 https 处理逻辑


- 2024-02-27  v0.26.18
  新增：nps.conf 新增 `tls_bridge_port=8025` 参数，当 `tls_enable=true` 时，nps 会监听8025端口，作为 tls 的连接端口

- 2024-01-31  v0.26.17
  说明：考虑到 npc 历史版本客户端众多，版本号不同旧版本客户端无法连接，为了兼容，仓库版本号将继续沿用 0.26.xx


- 2024-01-02  v0.27.01  (已作废，功能移动到v0.26.17 版本)
  新增：tls 流量加密

- 2023-06-01  v0.26.16
  修复：https 流量不统计 Bug 修复
  新增：新增全局黑名单IP，用于防止被肉鸡扫描端口或被恶意攻击
  新增：新增客户端上次在线时间

- 2023-02-24  v0.26.15
  修复：更新程序 url 更改到当前仓库中
  修复：nps 在外部路径启动时找不到配置文件
  新增：增加 nps 启动参数，`-conf_path=xxx`,可用于加载指定nps配置文件和web文件目录

- 2022-12-30  v0.26.14
  修复：API 鉴权漏洞修复

- 2022-12-19
  修复：某些场景下丢包导致服务端意外退出
  优化：新增隧道时，不指定服务端口时，将自动生成端口号
  优化：域名解析、隧道页面，增加唯一验证密钥，方便搜查

- 2022-10-30
  新增：在管理面板中新增客户端时，可以配置多个黑名单IP，用于防止被肉鸡扫描端口或被恶意攻击
  优化：还原了注册系统功能

- 2022-10-27
  新增：在管理面板登录时开启验证码校验，开启方式：nps.conf `open_captcha=true`

- 2022-10-24
  修复：HTTP协议支持WebSocket

- 2022-10-21
  修复：HTTP协议下实时统计流量，能够精准的限制住流量
  优化：删除HTTP隧道时，客户端已用流量不再清空

- 2022-10-19
  修复：TCP协议下实时统计流量，能够精准的限制住流量
  优化：删除TCP隧道时，客户端已用流量不再清空

- 2022-09-14
  修改NPS工作目录为当前可执行文件目录

# 赞助

如果你觉得这个项目对你有帮助，欢迎赞助支持！

| 支付宝 | 微信 |
|--------|------|
| ![支付宝](image/new/alipay.jpeg) | ![微信](image/new/wxpay.jpeg) |

# 许可证

MIT License
