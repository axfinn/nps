#!/bin/bash

# NPS项目发布脚本
# 用于更新版本号、创建GitHub标签并推送到远程仓库

set -e

# 设置UTF-8编码以避免乱码问题
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

help() {
    echo "用法: $0 <new_version>"
    echo "示例: $0 0.26.42"
    echo ""
    echo "参数:"
    echo "  new_version  新版本号，格式为 X.X.X"
    echo ""
    echo "功能:"
    echo "  1. 更新 lib/version/version.go 中的版本号"
    echo "  2. 更新 CHANGELOG.md 中的版本记录"
    echo "  3. 提交版本更改"
    echo "  4. 创建并推送Git标签"
    echo "  5. 推送更改到远程仓库"
}

# 检查参数
if [[ $# -ne 1 ]]; then
    help
    exit 1
fi

if [[ $1 == "-h" || $1 == "--help" ]]; then
    help
    exit 0
fi

NEW_VERSION=$1

# 验证版本号格式
if ! [[ $NEW_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "错误: 版本号格式不正确，应为 X.X.X 格式"
    exit 1
fi

# 获取当前版本号
CURRENT_VERSION=$(grep 'const VERSION =' lib/version/version.go | cut -d'"' -f2)

echo "当前版本: $CURRENT_VERSION"
echo "新版本: $NEW_VERSION"

if [[ $CURRENT_VERSION == $NEW_VERSION ]]; then
    echo "警告: 新版本号与当前版本号相同"
    read -p "是否继续? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# 检查是否有未提交的更改
if [[ -n $(git status --porcelain) ]]; then
    echo "错误: 存在未提交的更改，请先提交或暂存更改"
    exit 1
fi

echo "正在更新版本号..."

# 更新版本文件
sed -i.bak "s/const VERSION = \"$CURRENT_VERSION\"/const VERSION = \"$NEW_VERSION\"/" lib/version/version.go
rm lib/version/version.go.bak

echo "正在更新 CHANGELOG.md..."
# 在 CHANGELOG.md 中添加新版本条目
DATE=$(date +%Y-%m-%d)
sed -i.bak "1s/^/## [$NEW_VERSION] - $DATE\n\n### 新增\n\n-\n\n/" CHANGELOG.md
rm CHANGELOG.md.bak

echo "请输入此版本的变更内容，以 Ctrl+D 结束输入:"
echo "示例: 添加新功能X"
echo "     修复Y问题"
echo "     优化Z性能"
echo ""

# 读取用户输入的变更内容
CHANGELOG_CONTENT=""
while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ -n "$line" ]]; then
        CHANGELOG_CONTENT="$CHANGELOG_CONTENT- $line"$'\n'
    else
        CHANGELOG_CONTENT="$CHANGELOG_CONTENT"$'\n'
    fi
done

# 如果有输入变更内容，则更新CHANGELOG
if [[ -n "$CHANGELOG_CONTENT" && "$CHANGELOG_CONTENT" != $'\n' ]]; then
    # 移除最后的换行
    CHANGELOG_CONTENT=${CHANGELOG_CONTENT%$'\n'}
    # 替换占位符
    sed -i.bak "s/### 新增\n\n-/### 新增\n\n$CHANGELOG_CONTENT/" CHANGELOG.md
    rm CHANGELOG.md.bak
else
    # 如果没有输入内容，保留默认的占位符
    echo "未输入变更内容，保留默认占位符"
fi

echo "正在提交更改..."
# 添加更改到git
git add lib/version/version.go CHANGELOG.md

# 提交更改，使用UTF-8编码安全的提交信息
git -c i18n.commitEncoding=utf-8 -c i18n.logOutputEncoding=utf-8 commit -m "发布v$NEW_VERSION版本：更新版本号和变更日志"

echo "正在创建并推送标签..."
# 创建标签
git tag -a "v$NEW_VERSION" -m "发布v$NEW_VERSION版本"

# 推送提交
git push origin HEAD

# 推送标签
git push origin "v$NEW_VERSION"

echo "发布完成！"
echo "版本 $NEW_VERSION 已成功发布并推送到远程仓库"
echo "请记得在GitHub上发布此版本的Release说明"