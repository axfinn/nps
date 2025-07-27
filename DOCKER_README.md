# NPS Docker 镜像说明

[![Docker Pulls](https://img.shields.io/docker/pulls/yourusername/nps.svg)](https://hub.docker.com/r/yourusername/nps)
[![Docker Stars](https://img.shields.io/docker/stars/yourusername/nps.svg)](https://hub.docker.com/r/yourusername/nps)

NPS 是一款轻量级、高性能的内网穿透代理服务器，支持多种协议穿透，提供 Web 管理端。本镜像基于官方源码构建，支持多种架构平台。

## 镜像特性

- 🚀 **轻量级**: 基于 scratch 镜像构建，体积小，安全性高
- 🏗️ **多平台支持**: 支持 amd64、arm、arm64 架构
- 🔧 **易于配置**: 支持挂载外部配置文件
- 🔒 **安全**: 使用静态链接构建，减少依赖
- 🌐 **多功能**: 支持 TCP/UDP/HTTP/HTTPS/SOCKS5/P2P 等多种协议

## 支持的平台

- linux/amd64
- linux/arm
- linux/arm64

## 镜像标签

- `latest` - 最新稳定版本
- `vX.X.X` - 指定版本，例如 `v0.26.28`

## 使用方法

### 服务端 (nps)

```bash
# 拉取镜像
docker pull yourusername/nps:latest

# 运行服务端容器
docker run -d \
  --name nps \
  -p 8088:8088 \
  -p 8024:8024 \
  -p 8181:8181 \
  -v /path/to/conf:/conf \
  yourusername/nps:latest
```

### 客户端 (npc)

```bash
# 拉取镜像
docker pull yourusername/npc:latest

# 运行客户端容器
docker run -d \
  --name npc \
  -v /path/to/conf:/conf \
  yourusername/npc:latest \
  -server=your-nps-server:8024 -vkey=your-vkey
```

## 配置文件

### 服务端配置

将配置文件放在宿主机的 `/path/to/conf` 目录下，容器会自动读取以下配置文件：

- `nps.conf` - 主配置文件
- `clients.json` - 客户端配置
- `tasks.json` - 任务配置
- `hosts.json` - 域名配置

### 客户端配置

客户端可以通过命令行参数或配置文件进行配置：

#### 命令行参数方式

```bash
docker run -d --name npc yourusername/npc:latest \
  -server=your-nps-server:8024 \
  -vkey=your-vkey \
  -type=tcp
```

#### 配置文件方式

创建 `npc.conf` 文件：

```ini
[common]
server=your-nps-server:8024
vkey=your-vkey
type=tcp
```

然后挂载到容器中：

```bash
docker run -d --name npc \
  -v /path/to/conf:/conf \
  yourusername/npc:latest
```

## 端口说明

### 服务端端口

| 端口 | 用途 |
|------|------|
| 8088 | Web管理界面 |
| 8024 | 客户端连接端口 |
| 8181 | HTTP代理默认端口 |

## 环境变量

目前暂不支持通过环境变量配置，建议使用配置文件或命令行参数。

## 更新日志

请查看 [GitHub Releases](https://github.com/yourusername/nps/releases) 获取最新的更新日志。

## 问题反馈

如有任何问题，请提交 Issue 到 [GitHub 仓库](https://github.com/yourusername/nps/issues)。

## License

[MIT License](https://github.com/yourusername/nps/blob/master/LICENSE)