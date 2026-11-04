# libssh2-oh

使用 HarmonyOS 系统 CryptoFramework 的 libssh2 移植库，包版本 `0.1.0`，
上游基础版本 libssh2 1.11.1，包含来源清单锁定的安全修复和移植补丁。

本包提供 C/C++ 静态库，保留 libssh2 公共 C API；ArkTS 入口只导出版本常量。
平台为 HarmonyOS API 26、arm64-v8a、2in1，系统依赖为 `libohcrypto.so` 和 `libhilog_ndk.z.so`。
不捆绑 OpenSSL、Mbed TLS 或系统 CryptoFramework 实现。

## 安装

当前尚未发布到 OHPM，先引用本机 HAR：

```sh
ohpm install ./libssh2-oh-0.1.0.har
```

发布后可使用：

```sh
ohpm install libssh2-oh
```

## CMake 使用

在包含 C/C++ 的模块中安装 HAR 后，引入包内配置。以下假定 CMakeLists.txt 位于
`src/main/cpp`，`oh_modules` 位于模块根目录；请按实际依赖目录调整路径。

```cmake
include("${CMAKE_CURRENT_SOURCE_DIR}/../../../oh_modules/libssh2-oh/include/libssh2-oh.cmake")
target_link_libraries(your_native_target PRIVATE libssh2-oh::ssh2)
```

此目标传递头文件、静态库及系统链接依赖。不要同时链接另一份 libssh2，
也不要将 `.a` 当作运行时 `.so` 加载。

```c
#include <libssh2.h>
#include <libssh2_sftp.h>

/* 统一管理进程内初始化与退出，有活动会话时不能调用 libssh2_exit。 */
int initialize_ssh(void)
{
    return libssh2_init(0);
}
```

宿主应用声明 `ohos.permission.INTERNET`，并负责主机密钥校验、凭据存储、
线程、超时及会话释放。接口细节参见 [libssh2 API](https://libssh2.org/docs.html)。

## 算法

后端包含 SHA/HMAC、AES-CTR/GCM、RSA、ECDSA、Ed25519、X25519、ECDH 和 DH。
DH 使用协商的实际 p/g，覆盖 group1、group14、group16、group18 与 Group Exchange；
GEX 请求范围为 2048～8192 位。DSA、AES-CBC 和 FIDO 私钥入口不在本版范围内。

库保留上游方法列表，生产调用方应设置现代算法首选项，仅在明确选择兼容连接时允许 SHA-1。
Demo 的 SHA-1 开关默认关闭。

## 源码与许可

[DreamistW/libssh2-oh](https://github.com/DreamistW/libssh2-oh) 包含源码及构建脚本：
`scripts/build-native.py`、`scripts/build-har.ps1` 和 `scripts/build-demo.ps1`。
原生来源和哈希见包内 `include/libssh2-oh-manifest.json`。
原创后端及构建代码采用 Apache-2.0，libssh2 采用 BSD-3-Clause，完整许可随包提供。
