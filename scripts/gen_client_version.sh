#!/usr/bin/env bash
# 生成客户端版本清单 client-version.json，供 npc_gui 的「在线检查更新」使用。
#
# 用法: ./scripts/gen_client_version.sh <输出json> <gui包目录> [cli包目录]
#
# 清单必须与实际提供的 tar.gz 一起发布：Dockerfile.nps 的 assets 阶段在编译完
# 24 个包之后调用本脚本，最终镜像把清单 COPY 到 /web/static/download/。
# 客户端通过 <下载页base>/client-version.json 读取版本与每个包的 sha256/大小，
# 下载后逐字节校验，避免拿到截断包或错平台包直接覆盖线上服务。

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/web/static/download/client-version.json}"
GUI_DIR="${2:-$ROOT/web/static/download/gui}"
CLI_DIR="${3:-$ROOT/web/static/download/client}"

VERSION="$(grep -E '^const VERSION[[:space:]]*=' "$ROOT/lib/version/version.go" \
    | head -1 | sed -E 's/.*"([^"]+)".*/\1/')"
if [ -z "$VERSION" ]; then
    echo "gen_client_version.sh: 无法从 lib/version/version.go 读取 VERSION" >&2
    exit 1
fi
CORE="$(grep -A3 'func GetVersion' "$ROOT/lib/version/version.go" \
    | grep -oE '"[^"]+"' | head -1 | tr -d '"' || true)"
GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        openssl dgst -sha256 "$1" | awk '{print $NF}'
    fi
}

entries=()
add_pkg() {
    local file="$1" rel="$2"
    [ -f "$file" ] || return 0
    local name size hash stem rest os arch extra
    name="$(basename "$file")"
    size="$(wc -c < "$file" | tr -d '[:space:]')"
    hash="$(sha256_file "$file")"
    extra=""
    # 只有 GUI 包需要 os/arch：客户端按 npc_gui_<os>_<arch>.tar.gz 选包。
    case "$name" in
        npc_gui_*.tar.gz)
            stem="${name%.tar.gz}"
            rest="${stem#npc_gui_}"
            os="${rest%%_*}"
            arch="${rest#*_}"
            extra=", \"os\": \"$os\", \"arch\": \"$arch\""
            ;;
    esac
    entries+=("    {\"name\": \"$name\", \"path\": \"$rel/$name\", \"sha256\": \"$hash\", \"size\": $size$extra}")
}

for f in "$GUI_DIR"/*.tar.gz; do
    if [ -e "$f" ]; then add_pkg "$f" "gui"; fi
done
if [ -d "$CLI_DIR" ]; then
    for f in "$CLI_DIR"/*.tar.gz; do
        if [ -e "$f" ]; then add_pkg "$f" "client"; fi
    done
fi

mkdir -p "$(dirname "$OUT")"
{
    printf '{\n'
    printf '  "version": "%s",\n' "$VERSION"
    printf '  "core": "%s",\n' "$CORE"
    printf '  "generated_at": "%s",\n' "$GENERATED_AT"
    printf '  "packages": [\n'
    total="${#entries[@]}"
    if [ "$total" -gt 0 ]; then
        i=0
        for entry in "${entries[@]}"; do
            i=$((i + 1))
            if [ "$i" -lt "$total" ]; then
                printf '%s,\n' "$entry"
            else
                printf '%s\n' "$entry"
            fi
        done
    fi
    printf '  ]\n}\n'
} > "$OUT"

echo "gen_client_version.sh: 已写出 ${OUT}（v${VERSION}，${total} 个包）"
