# 原生构建输入

`dependencies.lock.json` 锁定 libssh2 上游版本、官方归档 SHA-256、安全修复和移植补丁。
`libssh2/ohcrypto` 为原创后端；`libssh2/patches/series` 定义完整应用顺序。
后端与上游许可证分别为 Apache-2.0、BSD-3-Clause，后者完整文本位于 `licenses`。

从工程根目录执行 `python3 scripts/build-native.py`。只构建 arm64-v8a、API 26、
OHCRYPTO 静态库，不构建示例、上游测试、zlib 或其他密码学后端。
原生构建只调用 `DEVECO_CLI_CLT_PATH` 指定 SDK 内的工具；GNU patch 由 PATH 提供。

下载和编译缓存位于工程 `build/native`，持久产物位于本目录 `prebuilt/arm64-v8a`，
均由 Git 忽略。`build-manifest.json` 绑定源码、构建参数与产物哈希，HAR 打包前再次验证。
