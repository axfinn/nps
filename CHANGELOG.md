# 变更日志

## [0.26.26] - 2025-07-26

### 优化
- 核心性能优化：减少锁竞争，使用原子操作替代部分锁操作，优化sync.Map遍历效率
- 流量统计优化：
  - 在Flow结构体中添加AtomicAdd和GetFlow方法，使用原子操作更新流量统计，避免锁竞争
  - 在BaseServer中添加FlowAddAtomic和FlowAddHostAtomic方法，使用原子操作更新流量
- 连接数管理优化：
  - 在Client结构体中优化GetConn方法，使用atomic.LoadInt32直接读取连接数，避免不必要的锁
  - 添加GetNowConn方法，用于原子地获取当前连接数
- sync.Map遍历优化：
  - 优化storeSyncMapToFile函数，使用goroutine和channel并行处理数据序列化和文件写入
  - 减少锁的持有时间，提高并发性能
- 服务器数据统计优化：
  - 在GetDashboardData函数中使用原子操作统计客户端连接数，避免锁竞争
- 接口实现修复：
  - 修复Bridge结构体，确保正确实现NetBridge接口

### 版本更新
- 项目版本从 v0.26.25 更新至 v0.26.26

## 2025-07-26

### 优化
- 简化 README.md 文件，移除过时和不必要的信息
- 更新 go.mod 文件，升级 beego 框架到 v2 版本
- 重构 server/server.go 文件，将全局变量封装到 Server 结构体中
- 在 proxy/base.go 中添加上下文支持，实现优雅关闭
- 在 common/util.go 中添加密码安全功能，使用 Argon2 算法进行密码哈希

### 依赖更新
- 更新 beego 从 v1.12.0 到 v2.1.0
- 更新 kcp-go 到 v5.4.20 正确版本
- 添加 golang.org/x/crypto 依赖用于密码安全功能

### 代码结构改进
- 引入 Server 结构体和单例模式管理服务实例
- 重构全局变量访问方式，提高代码可维护性
- 添加上下文支持，实现更好的资源管理

### 兼容性更新
- 更新所有 beego 导入路径以适配 v2 版本
- 修正相关 API 调用以符合新版本
### Bug修复
- 修复 npc_gui.go 中的 fmt.Errorf 参数不匹配问题
- 解决 cmd/npc 目录中 main 函数重复声明的问题
- 修复 config 包的测试用例问题

### 测试改进
- 修复 pmux 包中的端口冲突问题，更改测试端口从 8888 到 8899
- 修改 pmux 包避免在测试环境中直接调用 os.Exit
- 修改 nps_mux 包测试，使用本地回环地址替代 Docker 网络地址
- 为需要特定网络配置的测试添加跳过条件，提高测试可执行性
- 修复 nps_mux 包测试中的变量使用问题和导入问题