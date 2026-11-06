# libssh2-oh

基于 libssh2 1.11.1 的 HarmonyOS 移植，使用原创 OHCRYPTO 后端调用系统
`libohcrypto.so`。HAR 版本为 `0.1.1`，最低兼容版本为 API 23，编译目标为 API 26、arm64-v8a、2in1。

源码仓库：[DreamistW/libssh2-oh](https://github.com/DreamistW/libssh2-oh)。

## 工程内容

- `native/`：版本与补丁锁、OHCRYPTO 后端、补丁队列及第三方许可
- `library/`：HAR 模块、公共接口装配和 OHPM 说明
- `demo/`：直接依赖生成 HAR 的独立应用工程
- `scripts/`：原生编译、HAR 打包及 demo 构建所需脚本

本仓库不依赖原应用检出目录、特定构建主机或用户目录。
上游源码按锁文件从官方地址下载并校验，不提交 SDK、下载源码或二进制。

## 构建原生库

需要 Python 3.11+、GNU patch 和 API 26 HarmonyOS Command Line Tools。
SDK 根目录只从 `DEVECO_CLI_CLT_PATH` 读取。

在 Linux 构建环境、仓库根目录运行：

```sh
python3 scripts/build-native.py
```

脚本核对归档及所有补丁 SHA-256，按实际输入生成独立缓存，并校验已展开源码内容。
SDK 或编译器变化时使用独立 CMake 目录，避免复用旧编译器配置。
产物为 `native/prebuilt/arm64-v8a` 中的静态库、公共头文件和 `build-manifest.json`。
使用独立构建机时，只需将该目录回传到 Windows 工作副本的相同相对路径。

## 构建 HAR 与 Demo

本机需配置 `DEVECO_CLI_CLT_PATH`、Python、Java 和支持 `assembleHar` 的 `devecocli`。
从仓库根目录运行：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build-har.ps1
powershell -ExecutionPolicy Bypass -File scripts/build-demo.ps1
```

HAR 位于 `dist/libssh2-oh-0.1.1.har`。打包时强制核对原生来源清单，导出三个公共头文件、
静态库和 CMake 配置，保留完整许可并检查包内内容。产物与缓存均由 Git 忽略。

Demo HAP 位于 `demo/entry/build/default/outputs/default`，安装运行前需在本机配置调试签名。
运行和签名流程见 [demo/README.md](demo/README.md)，HAR 安装及调用见
[library/README.md](library/README.md)。

## 基本功能示例

连接与密码认证、命令执行、PTY 和 SFTP 上传下载示例见 [使用说明](library/README.md#基本功能示例)。

## GitHub Release

将与库版本一致的稳定标签（例如 `v0.1.1`）推送到 GitHub 后，Actions 构建 HAR 并将 HAR 和 SHA-256 校验文件发布为 Latest Release。GitHub 托管的 Ubuntu runner 自动拉取按摘要固定的社区工具链镜像（HarmonyOS API 26，CLT 26.0.0.821），编译原生库并校验 HAR。推送 main 会先执行相同构建。

## 许可

原创后端及构建脚本使用 Apache-2.0；libssh2 使用 BSD-3-Clause，完整许可及归属声明随包提供。
