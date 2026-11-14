#!/usr/bin/env bash
# 注意：本脚本用到 bash 的 $'...' 语法，CI 里直接 ./build.assets.sh 执行，
# 必须有 shebang，否则内核 ENOEXEC 后可能被 dash 解释而报错。
export GOPROXY=direct

sudo apt-get update
sudo apt-get install gcc-mingw-w64-i686 gcc-multilib
env GOOS=windows GOARCH=386 CGO_ENABLED=1 CC=i686-w64-mingw32-gcc go build -ldflags "-s -w -extldflags -static -extldflags -static" -buildmode=c-shared -o npc_sdk.dll cmd/npc/sdk.go
env GOOS=linux GOARCH=386 CGO_ENABLED=1 CC=gcc go build -ldflags "-s -w -extldflags -static -extldflags -static" -buildmode=c-shared -o npc_sdk.so cmd/npc/sdk.go
tar -czvf npc_sdk.tar.gz npc_sdk.dll npc_sdk.so npc_sdk.h

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -extldflags -static -extldflags -static"  ./cmd/npc/npc.go

tar -czvf linux_amd64_client.tar.gz npc 

CGO_ENABLED=0 GOOS=linux GOARCH=386 go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/npc/npc.go

tar -czvf linux_386_client.tar.gz npc 

CGO_ENABLED=0 GOOS=freebsd GOARCH=386 go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/npc/npc.go

tar -czvf freebsd_386_client.tar.gz npc 

CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/npc/npc.go

tar -czvf freebsd_amd64_client.tar.gz npc 

CGO_ENABLED=0 GOOS=freebsd GOARCH=arm go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/npc/npc.go

tar -czvf freebsd_arm_client.tar.gz npc 

CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/npc/npc.go

tar -czvf linux_arm_v7_client.tar.gz npc 

CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=6 go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/npc/npc.go

tar -czvf linux_arm_v6_client.tar.gz npc 

CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/npc/npc.go

tar -czvf linux_arm_v5_client.tar.gz npc 


CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/npc/npc.go

tar -czvf linux_arm64_client.tar.gz npc 


CGO_ENABLED=0 GOOS=linux GOARCH=mips64 go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/npc/npc.go

tar -czvf linux_mips64_client.tar.gz npc 


CGO_ENABLED=0 GOOS=linux GOARCH=mips64le go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/npc/npc.go

tar -czvf linux_mips64le_client.tar.gz npc 


CGO_ENABLED=0 GOOS=linux GOARCH=mipsle go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/npc/npc.go

tar -czvf linux_mipsle_client.tar.gz npc 


CGO_ENABLED=0 GOOS=linux GOARCH=mips go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/npc/npc.go

tar -czvf linux_mips_client.tar.gz npc 


CGO_ENABLED=0 GOOS=windows GOARCH=386 go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/npc/npc.go

tar -czvf windows_386_client.tar.gz npc.exe 


CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/npc/npc.go

tar -czvf windows_amd64_client.tar.gz npc.exe 


CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/npc/npc.go

tar -czvf darwin_amd64_client.tar.gz npc 

CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/npc/npc.go

tar -czvf darwin_arm64_client.tar.gz npc 


CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/nps/nps.go

tar -czvf linux_amd64_server.tar.gz conf/nps.conf conf/tasks.json conf/clients.json conf/hosts.json conf/server.key  conf/server.pem web/views web/static nps

CGO_ENABLED=0 GOOS=linux GOARCH=386 go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/nps/nps.go

tar -czvf linux_386_server.tar.gz conf/nps.conf conf/tasks.json conf/clients.json conf/hosts.json conf/server.key  conf/server.pem web/views web/static nps

CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/nps/nps.go

tar -czvf linux_arm_v5_server.tar.gz conf/nps.conf conf/tasks.json conf/clients.json conf/hosts.json conf/server.key  conf/server.pem web/views web/static nps

CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=6 go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/nps/nps.go

tar -czvf linux_arm_v6_server.tar.gz conf/nps.conf conf/tasks.json conf/clients.json conf/hosts.json conf/server.key  conf/server.pem web/views web/static nps

CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/nps/nps.go

tar -czvf linux_arm_v7_server.tar.gz conf/nps.conf conf/tasks.json conf/clients.json conf/hosts.json conf/server.key  conf/server.pem web/views web/static nps


CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/nps/nps.go

tar -czvf linux_arm64_server.tar.gz conf/nps.conf conf/tasks.json conf/clients.json conf/hosts.json conf/server.key  conf/server.pem web/views web/static nps


CGO_ENABLED=0 GOOS=freebsd GOARCH=arm go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/nps/nps.go

tar -czvf freebsd_arm_server.tar.gz conf/nps.conf conf/tasks.json conf/clients.json conf/hosts.json conf/server.key  conf/server.pem web/views web/static nps


CGO_ENABLED=0 GOOS=freebsd GOARCH=386 go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/nps/nps.go

tar -czvf freebsd_386_server.tar.gz conf/nps.conf conf/tasks.json conf/clients.json conf/hosts.json conf/server.key  conf/server.pem web/views web/static nps


CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/nps/nps.go

tar -czvf freebsd_amd64_server.tar.gz conf/nps.conf conf/tasks.json conf/clients.json conf/hosts.json conf/server.key  conf/server.pem web/views web/static nps



CGO_ENABLED=0 GOOS=linux GOARCH=mips go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/nps/nps.go

tar -czvf linux_mips_server.tar.gz conf/nps.conf conf/tasks.json conf/clients.json conf/hosts.json conf/server.key  conf/server.pem web/views web/static nps


CGO_ENABLED=0 GOOS=linux GOARCH=mips64 go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/nps/nps.go

tar -czvf linux_mips64_server.tar.gz conf/nps.conf conf/tasks.json conf/clients.json conf/hosts.json conf/server.key  conf/server.pem web/views web/static nps


CGO_ENABLED=0 GOOS=linux GOARCH=mips64le go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/nps/nps.go

tar -czvf linux_mips64le_server.tar.gz conf/nps.conf conf/tasks.json conf/clients.json conf/hosts.json conf/server.key  conf/server.pem web/views web/static nps


CGO_ENABLED=0 GOOS=linux GOARCH=mipsle go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/nps/nps.go

tar -czvf linux_mipsle_server.tar.gz conf/nps.conf conf/tasks.json conf/clients.json conf/hosts.json conf/server.key  conf/server.pem web/views web/static nps



CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/nps/nps.go

tar -czvf darwin_amd64_server.tar.gz conf/nps.conf conf/tasks.json conf/clients.json conf/hosts.json conf/server.key  conf/server.pem web/views web/static nps


CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/nps/nps.go

tar -czvf darwin_arm64_server.tar.gz conf/nps.conf conf/tasks.json conf/clients.json conf/hosts.json conf/server.key  conf/server.pem web/views web/static nps



CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/nps/nps.go

tar -czvf windows_amd64_server.tar.gz conf/nps.conf conf/tasks.json conf/clients.json conf/hosts.json conf/server.key  conf/server.pem web/views web/static nps.exe


CGO_ENABLED=0 GOOS=windows GOARCH=386 go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/nps/nps.go

tar -czvf windows_386_server.tar.gz conf/nps.conf conf/tasks.json conf/clients.json conf/hosts.json conf/server.key  conf/server.pem web/views web/static nps.exe

# ---- Web GUI 客户端 (npc_gui) ----
# 下载页 web/views/index/download.html 已列出这 7 个包，但此前没有构建步骤。
# 必须整包构建（go build ./gui/npc），不能用单文件 nps.go/npc.go 的方式：
# gui/npc/static/* 是通过 go:embed 打进二进制的，单文件构建会丢失静态页面。
# 状态栏用系统自带脚本引擎实现，因此这里继续保持 CGO_ENABLED=0 交叉编译。

# ---- 可选：编译期预置连接参数（定制发行包） ----
# 不设置下面这些变量时，7 个包仍是「打开面板自己填服务器/vkey」的通用客户端，
# 行为与之前完全一致。设置了才会通过 -ldflags -X 把默认值烧进二进制。
#
#   NPC_GUI_SERVER=你的服务器:8024 \
#   NPC_GUI_VKEY=你的vkey \
#   NPC_GUI_LABEL="某某专用" \
#   ./build.assets.sh
#
# 生成的客户端可用 ./npc_gui -print-config 核对预置值（vkey 打码显示）。
# 真实地址/密钥绝不写进仓库：只在构建时由本地环境变量或 CI Secret 提供。
NPC_GUI_LDFLAGS="-s -w"
npc_gui_ldflag() {
  [ -z "${2:-}" ] && return 0
  # 单/双引号、反引号、反斜杠、换行会破坏 -ldflags 的引号解析，直接拒绝；
  # 空格与中文（定制标签）是允许的，由外层单引号包住。
  case "$2" in
    *"'"*|*'"'*|*'`'*|*'\'*|*$'\n'*|*$'\r'*)
      echo "build.assets.sh: NPC_GUI_* 的值含非法字符，已中止: $1" >&2
      return 1
      ;;
  esac
  NPC_GUI_LDFLAGS="$NPC_GUI_LDFLAGS -X 'main.$1=$2'"
}
npc_gui_ldflag buildServer            "${NPC_GUI_SERVER:-}"            || exit 1
npc_gui_ldflag buildVkey              "${NPC_GUI_VKEY:-}"              || exit 1
npc_gui_ldflag buildConnType          "${NPC_GUI_TYPE:-}"              || exit 1
npc_gui_ldflag buildTlsEnable         "${NPC_GUI_TLS:-}"               || exit 1
npc_gui_ldflag buildProxyUrl          "${NPC_GUI_PROXY:-}"             || exit 1
npc_gui_ldflag buildDisconnectTimeout "${NPC_GUI_DISCONNECT_TIMEOUT:-}" || exit 1
npc_gui_ldflag buildLabel             "${NPC_GUI_LABEL:-}"             || exit 1
npc_gui_ldflag buildUpdateURL         "${NPC_GUI_UPDATE_URL:-}"          || exit 1

CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "$NPC_GUI_LDFLAGS" -o npc_gui.exe ./gui/npc
tar -czvf npc_gui_windows_amd64.tar.gz npc_gui.exe

CGO_ENABLED=0 GOOS=windows GOARCH=386 go build -ldflags "$NPC_GUI_LDFLAGS" -o npc_gui.exe ./gui/npc
tar -czvf npc_gui_windows_386.tar.gz npc_gui.exe

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$NPC_GUI_LDFLAGS" -o npc_gui ./gui/npc
tar -czvf npc_gui_linux_amd64.tar.gz npc_gui

CGO_ENABLED=0 GOOS=linux GOARCH=386 go build -ldflags "$NPC_GUI_LDFLAGS" -o npc_gui ./gui/npc
tar -czvf npc_gui_linux_386.tar.gz npc_gui

CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$NPC_GUI_LDFLAGS" -o npc_gui ./gui/npc
tar -czvf npc_gui_linux_arm64.tar.gz npc_gui

CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "$NPC_GUI_LDFLAGS" -o npc_gui ./gui/npc
tar -czvf npc_gui_darwin_amd64.tar.gz npc_gui

CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags "$NPC_GUI_LDFLAGS" -o npc_gui ./gui/npc
tar -czvf npc_gui_darwin_arm64.tar.gz npc_gui

# 生成在线检查更新用的版本清单（仓库静态包目录存在时）。
# 先把本次编译出的 7 个 GUI 包同步进目录，保证清单里的 version 与包内二进制版本一致；
# 镜像里由 Dockerfile.nps 的 assets 阶段针对本次编译产物单独生成，二者互不依赖。
if [ -d web/static/download/gui ]; then
  for f in npc_gui_*.tar.gz; do
    if [ -e "$f" ]; then cp -f "$f" web/static/download/gui/; fi
  done
  bash ./scripts/gen_client_version.sh \
    web/static/download/client-version.json \
    web/static/download/gui web/static/download/client
fi
