# libssh2-oh

使用 HarmonyOS 系统 CryptoFramework 的 libssh2 移植库，包版本 `0.1.1`，
上游基础版本 libssh2 1.11.1，包含来源清单锁定的安全修复和移植补丁。

本包提供 C/C++ 静态库，保留 libssh2 公共 C API；ArkTS 入口只导出版本常量。
最低兼容声明为 HarmonyOS API 23，编译目标及已验证设备为 API 26；支持 arm64-v8a、2in1，系统依赖为 `libohcrypto.so` 和 `libhilog_ndk.z.so`。
不捆绑 OpenSSL、Mbed TLS 或系统 CryptoFramework 实现。

## 安装与接入

在宿主应用的原生模块目录安装：

```sh
ohpm install libssh2-oh
```

离线使用 GitHub Release 的 HAR：

```sh
ohpm install ./libssh2-oh-0.1.1.har
```

宿主模块的 `module.json5` 中声明网络权限：

```json
"requestPermissions": [
  { "name": "ohos.permission.INTERNET" }
]
```

假设 CMakeLists.txt 位于模块的 `src/main/cpp`，`oh_modules` 位于模块根目录：

```cmake
include("${CMAKE_CURRENT_SOURCE_DIR}/../../../oh_modules/libssh2-oh/include/libssh2-oh.cmake")
target_link_libraries(your_native_target PRIVATE libssh2-oh::ssh2)
```

导入目标传递公共头文件、静态库及系统链接依赖。宿主通过自己的 NAPI 桥接层调用这些 C API。

## 基本功能示例

以下 C++ 示例运行在原生工作线程。会话采用阻塞模式，设置 10 秒操作超时。
`socketFd` 由宿主通过 POSIX socket 完成 TCP 连接并保持为阻塞模式，连接本身的超时由宿主管理。
会话独占该连接，示例结束后宿主负责关闭 socket。密码和可信主机指纹由调用方传入。

### 初始化、SSH 握手、主机校验与密码认证

进程启动时调用一次 `libssh2_init(0)` 并检查返回值；所有会话结束后才调用 `libssh2_exit()`。
下面函数返回经过认证的会话，失败返回空指针。

```cpp
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <array>
#include <cstring>
#include <string>

LIBSSH2_SESSION *ConnectSsh(int socketFd,
    const std::array<unsigned char, 32> &trustedSha256,
    const std::string &username, const std::string &password)
{
    // 长度限制也保证后续转换到 unsigned int 不发生截断。
    if (username.empty() || username.size() > 1024 || password.size() > 4096) {
        return nullptr;
    }
    LIBSSH2_SESSION *session = libssh2_session_init();
    if (!session) {
        return nullptr;
    }
    libssh2_session_set_blocking(session, 1);
    libssh2_session_set_timeout(session, 10000);
    int rc = libssh2_session_handshake(session, socketFd);
    const char *hash = rc == 0
        ? libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA256) : nullptr;
    // trustedSha256 是从可信渠道取得的 32 字节原始摘要，不是 Base64 文本。
    if (!hash || std::memcmp(hash, trustedSha256.data(), trustedSha256.size()) != 0) {
        libssh2_session_free(session);
        return nullptr;
    }
    rc = libssh2_userauth_password_ex(session, username.data(),
        static_cast<unsigned int>(username.size()), password.data(),
        static_cast<unsigned int>(password.size()), nullptr);
    if (rc != 0) {
        libssh2_session_disconnect(session, "authentication failed");
        libssh2_session_free(session);
        return nullptr;
    }
    return session;
}
```

主机校验必须在发送凭据前完成。首次连接时由用户核实主机指纹并持久化信任记录。
生产调用方可在握手前通过 `libssh2_session_method_pref` 设置算法策略。

### 执行命令并读取输出

以下使用固定命令，合并 stderr，避免只读取 stdout 时另一条流阻塞。
输出上限为 64 KiB，适用于短命令。

```cpp
bool ExecuteCommand(LIBSSH2_SESSION *session, std::string &output)
{
    output.clear();
    LIBSSH2_CHANNEL *channel = libssh2_channel_open_session(session);
    if (!channel) {
        return false;
    }
    int rc = libssh2_channel_handle_extended_data2(channel, LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE);
    if (rc == 0) {
        rc = libssh2_channel_exec(channel, "printf 'hello from libssh2-oh\n'");
    }
    bool ok = rc == 0;
    char buffer[4096];
    while (ok) {
        const auto count = libssh2_channel_read(channel, buffer, sizeof(buffer));
        if (count < 0) { ok = false; break; }
        if (count == 0) { ok = libssh2_channel_eof(channel) != 0; break; }
        if (output.size() + static_cast<size_t>(count) > 65536) { ok = false; break; }
        output.append(buffer, static_cast<size_t>(count));
    }
    if (libssh2_channel_close(channel) != 0) { ok = false; }
    if (libssh2_channel_get_exit_status(channel) != 0) { ok = false; }
    if (libssh2_channel_free(channel) != 0) { ok = false; }
    return ok;
}
```

### 创建交互终端

在新 channel 上依次调用 `libssh2_channel_request_pty(channel, "xterm")` 和
`libssh2_channel_shell(channel)`，每一步检查返回值。终端输入通过
`libssh2_channel_write` 发送，输出通过 `libssh2_channel_read` 读取。
写入可能只完成部分字节，需推进偏移继续写入。交互终端建议采用非阻塞事件循环，
处理 `LIBSSH2_ERROR_EAGAIN`，结合 `libssh2_session_block_directions` 等待 socket 就绪。

### SFTP 上传与下载

以下函数接受已通过 `libssh2_sftp_init(session)` 创建的 SFTP 对象。
上传使用独占创建，目标已存在时返回失败。网络故障后可能留下部分文件，由调用方明确决定重试或清理。

```cpp
bool Upload(LIBSSH2_SFTP *sftp, const std::string &remotePath, const std::string &data)
{
    auto *file = libssh2_sftp_open(sftp, remotePath.c_str(),
        LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_EXCL, 0600);
    if (!file) { return false; }
    size_t offset = 0;
    while (offset < data.size()) {
        const auto count = libssh2_sftp_write(file, data.data() + offset, data.size() - offset);
        if (count <= 0) { break; }
        offset += static_cast<size_t>(count);
    }
    const int rc = libssh2_sftp_close(file);
    return offset == data.size() && rc == 0;
}

bool Download(LIBSSH2_SFTP *sftp, const std::string &remotePath, std::string &data)
{
    data.clear();
    auto *file = libssh2_sftp_open(sftp, remotePath.c_str(), LIBSSH2_FXF_READ, 0);
    if (!file) { return false; }
    bool ok = false;
    char buffer[4096];
    for (;;) {
        const auto count = libssh2_sftp_read(file, buffer, sizeof(buffer));
        if (count == 0) { ok = true; break; }
        if (count < 0 || data.size() + static_cast<size_t>(count) > 1024 * 1024) { break; }
        data.append(buffer, static_cast<size_t>(count));
    }
    if (libssh2_sftp_close(file) != 0) { ok = false; }
    if (!ok) { data.clear(); }
    return ok;
}
```

`std::string` 在这里保存二进制字节，支持包含零字节的数据。下载示例限制为 1 MiB；
大文件请分块写入本地文件，并处理本地 I/O 错误。

### 释放资源

先关闭所有文件、目录及 channel，再关闭 SFTP，最后断开会话并关闭 TCP socket：

```cpp
// sftp 和 session 均为成功创建、且没有其他使用者的有效对象。
int sftpRc = libssh2_sftp_shutdown(sftp);
int disconnectRc = libssh2_session_disconnect(session, "client finished");
int freeRc = libssh2_session_free(session);
// 宿主记录错误码并关闭 socketFd；所有会话结束后再 libssh2_exit()。
```

## 常用接口

| 功能 | libssh2 接口 |
|---|---|
| 初始化与退出 | libssh2_init / libssh2_exit |
| 握手、指纹、认证 | libssh2_session_handshake / libssh2_hostkey_hash / libssh2_userauth_password_ex |
| 命令与终端 | libssh2_channel_exec / libssh2_channel_request_pty / libssh2_channel_shell |
| 通道读写 | libssh2_channel_read / libssh2_channel_write |
| SFTP 文件操作 | libssh2_sftp_open / libssh2_sftp_read / libssh2_sftp_write / libssh2_sftp_close |
| SFTP 目录操作 | libssh2_sftp_opendir / libssh2_sftp_readdir / libssh2_sftp_closedir |

完整参数和返回值见 [libssh2 API 文档](https://libssh2.org/docs.html)。

## 约束与注意事项

- 最低兼容声明为 API 23；目前真机验证覆盖 API 26，API 23 运行兼容性尚待验证。
- 同一 session 的操作由宿主串行管理，阻塞网络操作放在工作线程执行。
- 超时设置限制单次阻塞操作；长时间持续有数据的任务还应由宿主设置总时限和取消机制。
- 密码、私钥与会话内容由宿主保护，不写入日志；示例不保存凭据。
- 目录、远端路径和命令由调用方校验，避免将未经处理的用户输入拼接成 shell 命令。

## 算法

后端包含 SHA/HMAC、AES-CTR/GCM、RSA、ECDSA、Ed25519、X25519、ECDH 和 DH。
DH 使用协商的实际 p/g，覆盖 group1、group14、group16、group18 与 Group Exchange；
GEX 请求范围为 2048～8192 位。DSA、AES-CBC 和 FIDO 私钥入口不在本版范围内。

库保留上游方法列表，生产调用方应设置现代算法首选项，仅在明确选择兼容连接时允许 SHA-1。
Demo 的 SHA-1 开关默认关闭。

## 目录与示例工程

仓库 `native/` 保存后端和补丁，`library/` 保存 HAR 模块，
`scripts/` 提供构建入口，`demo/` 提供完整 NAPI 工作线程、连接和 SFTP 流程。
参见 [独立 Demo](https://github.com/DreamistW/libssh2-oh/tree/main/demo)。

## 贡献

请通过源码仓库 Issue 报告问题，附上 SDK 版本、复现步骤和脱敏后的错误码。
代码修改可提交 Pull Request。

## 源码与许可

[DreamistW/libssh2-oh](https://github.com/DreamistW/libssh2-oh) 包含源码及构建脚本：
`scripts/build-native.py`、`scripts/build-har.ps1` 和 `scripts/build-demo.ps1`。
原生来源和哈希见包内 `include/libssh2-oh-manifest.json`。
原创后端及构建代码采用 Apache-2.0，libssh2 采用 BSD-3-Clause，完整许可随包提供。
