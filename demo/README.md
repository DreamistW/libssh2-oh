# Demo

本目录是独立 Stage 应用工程，API 26、arm64-v8a、仅 2in1。
`entry/oh-package.json5` 依赖 `../../dist/libssh2-oh-0.1.0.har`，不会直接编译库源码。

先在仓库根目录构建库和 demo：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build-har.ps1
powershell -ExecutionPolicy Bypass -File scripts/build-demo.ps1
```

构建脚本核对实际安装的静态库与本轮 HAR，并干净构建，避免外部 `.a` 变化未触发重链。

## 本机签名与运行

Git 中的 `demo/build-profile.json5` 必须保持 `signingConfigs: []`。
对于已跟踪的配置文件，先在本机设置隔离，再初始化调试签名：

```powershell
git update-index --skip-worktree demo/build-profile.json5
cd demo
devecocli signature generate --product default
```

签名缓存、证书、profile 和密钥不得提交或上传。签名后回到仓库根目录重建 demo。
通过 `devecocli device list --format json` 查询并确认 2in1 目标，再在 demo 目录显式指定目标运行：

```sh
devecocli run --module entry --device <已确认的2in1选择器> --skip-build
```

## 使用

填写用户控制的 SSH 主机、端口、用户名、密码和预先核对的 SHA-256 主机密钥指纹，选择 KEX 后运行。
参数仅保存在内存，指纹不匹配时不会发送认证信息；SHA-1 需显式开启旧版 DH 开关。

Demo 依次执行连接、主机校验、密码认证、PTY、固定命令和 SFTP 上传、下载、列表、清理及断开。
远端需支持 POSIX `printf`、SFTP 子系统，并允许账号在 home 目录写入。
SFTP 以独占方式创建随机临时文件，往返 196613 字节二进制数据，逐字节比较后删除。

本 demo 不包含完整终端、私钥认证或 SCP 界面。
