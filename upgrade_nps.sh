#!/bin/bash

# 升级 NPS 容器镜像的脚本
echo "开始升级 NPS 容器..."

# 定义变量
CONTAINER_NAME="nps"
IMAGE_NAME="yisier1/nps"
BACKUP_DIR="/root/docker/nps/backups"
CONFIG_DIR="/root/docker/nps/conf"

# 创建备份目录
mkdir -p $BACKUP_DIR

# 备份当前配置
echo "正在备份当前配置..."
cp -r $CONFIG_DIR $BACKUP_DIR/conf.backup.$(date +%Y%m%d-%H%M%S)

# 停止并删除当前容器
echo "正在停止容器..."
docker stop $CONTAINER_NAME

echo "正在删除旧容器..."
docker rm $CONTAINER_NAME

# 拉取最新镜像
echo "正在拉取最新镜像..."
docker pull $IMAGE_NAME:latest

# 启动新容器
echo "正在启动新容器..."
docker run -d \
  --name $CONTAINER_NAME \
  --restart=always \
  -v $CONFIG_DIR:/conf \
  -v /etc/localtime:/etc/localtime:ro \
  --net=host \
  $IMAGE_NAME:latest

# 验证
echo "等待容器启动..."
sleep 10

if docker ps | grep -q $CONTAINER_NAME; then
    echo "容器升级成功！"
    echo "查看容器日志："
    docker logs $CONTAINER_NAME
else
    echo "容器启动失败，请检查日志："
    docker logs $CONTAINER_NAME
fi