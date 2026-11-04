#include <napi/native_api.h>
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cerrno>
#include <cmath>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {
// 演示只允许一个运行中的请求；所有网络 I/O 均在异步工作线程执行。
std::atomic<bool> active {false};
std::once_flag initialization;
int initializationCode = -1;
constexpr int TIMEOUT_MS = 15000;

// 凭据的受控副本在完成和错误路径均清零。
void Clear(std::string &value)
{
    volatile char *bytes = value.empty() ? nullptr : value.data();
    for (size_t i = 0; i < value.size(); ++i) { bytes[i] = 0; }
    value.clear();
}

// NAPI 参数的工作线程副本不写入日志或本地存储。
struct Options {
    std::string host, username, password, fingerprint, kex;
    uint16_t port = 22;
    bool legacy = false;
    ~Options() { Clear(password); }
};

// 结果仅包含固定阶段和错误，不包含服务端正文或连接凭据。
struct Result {
    bool ok = false;
    std::string error, algorithm;
    int code = 0;
    std::vector<std::string> stages;
    bool Fail(const char *message, int value = -1) { error = message; code = value; return false; }
};

// 所有远端写入均使用独占创建的随机临时文件，退出时尽力清理。
struct Client {
    int socket = -1;
    LIBSSH2_SESSION *session = nullptr;
    LIBSSH2_CHANNEL *channel = nullptr;
    LIBSSH2_SFTP *sftp = nullptr;
    LIBSSH2_SFTP_HANDLE *file = nullptr;
    LIBSSH2_SFTP_HANDLE *directory = nullptr;
    std::string temporary;
    ~Client()
    {
        if (file) { libssh2_sftp_close(file); }
        if (directory) { libssh2_sftp_closedir(directory); }
        if (!temporary.empty() && sftp) { libssh2_sftp_unlink(sftp, temporary.c_str()); }
        if (sftp) { libssh2_sftp_shutdown(sftp); }
        if (channel) { libssh2_channel_free(channel); }
        if (session) { libssh2_session_disconnect(session, "demo complete"); libssh2_session_free(session); }
        if (socket >= 0) { close(socket); }
    }
};

// 连接使用统一总期限；地址与密码不进入报告或日志。
bool Connect(Client &client, const Options &options)
{
    addrinfo hints {}, *addresses = nullptr;
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    const auto service = std::to_string(options.port);
    if (getaddrinfo(options.host.c_str(), service.c_str(), &hints, &addresses) != 0) { return false; }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(TIMEOUT_MS);
    for (auto address = addresses; address && std::chrono::steady_clock::now() < deadline;
         address = address->ai_next) {
        int fd = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (fd < 0) { continue; }
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) { close(fd); continue; }
        int rc = connect(fd, address->ai_addr, address->ai_addrlen);
        if (rc != 0 && errno == EINPROGRESS) {
            pollfd poller {fd, POLLOUT, 0};
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now()).count();
            rc = remaining > 0 ? poll(&poller, 1, static_cast<int>(remaining)) : -1;
            int error = -1; socklen_t length = sizeof(error);
            rc = rc > 0 && getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == 0 ? 0 : -1;
        }
        if (rc == 0 && fcntl(fd, F_SETFL, flags) == 0) {
            timeval timeout {TIMEOUT_MS / 1000, 0};
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
            client.socket = fd; break;
        }
        close(fd);
    }
    freeaddrinfo(addresses);
    return client.socket >= 0;
}

// 输出与 OpenSSH 一致的无填充 SHA-256 指纹。
std::string Fingerprint(const unsigned char *bytes)
{
    constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string value = "SHA256:";
    for (size_t i = 0; i < 32; i += 3) {
        uint32_t block = static_cast<uint32_t>(bytes[i]) << 16;
        if (i + 1 < 32) { block |= static_cast<uint32_t>(bytes[i + 1]) << 8; }
        if (i + 2 < 32) { block |= bytes[i + 2]; }
        value += alphabet[(block >> 18) & 63]; value += alphabet[(block >> 12) & 63];
        if (i + 1 < 32) { value += alphabet[(block >> 6) & 63]; }
        if (i + 2 < 32) { value += alphabet[block & 63]; }
    }
    return value;
}

// 使用真实 PTY 执行固定命令，校验输出标记及退出状态。
bool Execute(Client &client, Result &result)
{
    client.channel = libssh2_channel_open_session(client.session);
    if (!client.channel) { return result.Fail("PTY channel failed", libssh2_session_last_errno(client.session)); }
    int rc = libssh2_channel_request_pty(client.channel, "xterm");
    if (rc != 0) { return result.Fail("PTY request failed", rc); }
    result.stages.push_back("pty");
    rc = libssh2_channel_exec(client.channel, "printf 'libssh2-oh-demo-ok\\n'");
    if (rc != 0) { return result.Fail("Command start failed", rc); }
    std::string output;
    std::array<char, 1024> block {};
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(TIMEOUT_MS);
    while (!libssh2_channel_eof(client.channel) && output.size() < 4096 &&
           std::chrono::steady_clock::now() < deadline) {
        const auto size = libssh2_channel_read(client.channel, block.data(), block.size());
        if (size < 0) { return result.Fail("Command read failed", static_cast<int>(size)); }
        if (size == 0) { std::this_thread::sleep_for(std::chrono::milliseconds(2)); }
        else { output.append(block.data(), static_cast<size_t>(size)); }
    }
    rc = libssh2_channel_close(client.channel);
    if (rc != 0 || output.find("libssh2-oh-demo-ok") == std::string::npos ||
        libssh2_channel_get_exit_status(client.channel) != 0) { return result.Fail("Command result mismatch", rc); }
    rc = libssh2_channel_free(client.channel); client.channel = nullptr;
    if (rc != 0) { return result.Fail("Command channel cleanup failed", rc); }
    result.stages.push_back("command");
    return true;
}

// 二进制往返、目录枚举和独占临时文件清理共用当前 SSH 会话。
bool Transfer(Client &client, Result &result)
{
    client.sftp = libssh2_sftp_init(client.session);
    if (!client.sftp) { return result.Fail("SFTP initialization failed", libssh2_session_last_errno(client.session)); }
    std::array<char, 4096> home {};
    int size = libssh2_sftp_realpath(client.sftp, ".", home.data(), home.size());
    if (size <= 0 || static_cast<size_t>(size) >= home.size()) { return result.Fail("SFTP home lookup failed", size); }
    const std::string directory(home.data(), static_cast<size_t>(size));
    std::array<unsigned char, 16> random {};
    if (getentropy(random.data(), random.size()) != 0) { return result.Fail("Temporary name unavailable"); }
    std::string path = directory + "/.libssh2-oh-demo-";
    constexpr char hex[] = "0123456789abcdef";
    for (auto byte : random) { path += hex[byte >> 4]; path += hex[byte & 15]; }
    client.file = libssh2_sftp_open(client.sftp, path.c_str(),
        LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_EXCL, 0600);
    if (!client.file) { return result.Fail("SFTP exclusive create failed", libssh2_session_last_errno(client.session)); }
    client.temporary = path;
    std::vector<unsigned char> payload(196613);
    for (size_t i = 0; i < payload.size(); ++i) { payload[i] = static_cast<unsigned char>((i * 37U + 11U) & 255U); }
    size_t offset = 0;
    while (offset < payload.size()) {
        const auto count = libssh2_sftp_write(client.file, reinterpret_cast<const char *>(payload.data() + offset),
            std::min<size_t>(65536, payload.size() - offset));
        if (count <= 0) { return result.Fail("SFTP upload failed", static_cast<int>(count)); }
        offset += static_cast<size_t>(count);
    }
    int rc = libssh2_sftp_close(client.file); client.file = nullptr;
    if (rc != 0) { return result.Fail("SFTP upload close failed", rc); }
    result.stages.push_back("sftp-upload");
    client.file = libssh2_sftp_open(client.sftp, path.c_str(), LIBSSH2_FXF_READ, 0);
    if (!client.file) { return result.Fail("SFTP read open failed", libssh2_session_last_errno(client.session)); }
    std::array<char, 65536> received {};
    offset = 0;
    while (offset < payload.size()) {
        const auto count = libssh2_sftp_read(client.file, received.data(),
            std::min(received.size(), payload.size() - offset));
        if (count <= 0 || memcmp(received.data(), payload.data() + offset, static_cast<size_t>(count)) != 0) {
            return result.Fail("SFTP download content mismatch", static_cast<int>(count));
        }
        offset += static_cast<size_t>(count);
    }
    if (libssh2_sftp_read(client.file, received.data(), 1) != 0) { return result.Fail("SFTP download size mismatch"); }
    rc = libssh2_sftp_close(client.file); client.file = nullptr;
    if (rc != 0) { return result.Fail("SFTP download close failed", rc); }
    result.stages.push_back("sftp-download");
    client.directory = libssh2_sftp_opendir(client.sftp, directory.c_str());
    if (!client.directory) { return result.Fail("SFTP directory open failed"); }
    bool found = false;
    const auto filename = path.substr(path.rfind('/') + 1);
    for (size_t i = 0; i < 10000; ++i) {
        LIBSSH2_SFTP_ATTRIBUTES attributes {};
        int length = libssh2_sftp_readdir(client.directory, received.data(), received.size(), &attributes);
        if (length < 0) { return result.Fail("SFTP directory read failed", length); }
        if (length == 0) { break; }
        if (std::string(received.data(), static_cast<size_t>(length)) == filename) { found = true; break; }
    }
    rc = libssh2_sftp_closedir(client.directory); client.directory = nullptr;
    if (!found || rc != 0) { return result.Fail("SFTP directory result mismatch", rc); }
    result.stages.push_back("sftp-list");
    rc = libssh2_sftp_unlink(client.sftp, path.c_str());
    if (rc != 0) { return result.Fail("SFTP temporary file cleanup failed", rc); }
    client.temporary.clear();
    result.stages.push_back("sftp-cleanup");
    return true;
}

// 主机指纹匹配之前不发送任何认证信息。
void Run(Options &options, Result &result)
{
    std::call_once(initialization, []() { initializationCode = libssh2_init(0); });
    if (initializationCode != 0) { result.Fail("SSH initialization failed", initializationCode); return; }
    Client client;
    if (!Connect(client, options)) { result.Fail("TCP connection failed"); return; }
    result.stages.push_back("connect");
    client.session = libssh2_session_init();
    if (!client.session) { result.Fail("SSH session allocation failed"); return; }
    libssh2_session_set_blocking(client.session, 1);
    libssh2_session_set_timeout(client.session, TIMEOUT_MS);
    int rc = libssh2_session_method_pref(client.session, LIBSSH2_METHOD_KEX, options.kex.c_str());
    if (rc == 0) { rc = libssh2_session_method_pref(client.session, LIBSSH2_METHOD_HOSTKEY,
        "ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256"); }
    if (rc == 0) { rc = libssh2_session_handshake(client.session, client.socket); }
    if (rc != 0) { result.Fail("SSH handshake failed", rc); return; }
    const char *algorithm = libssh2_session_methods(client.session, LIBSSH2_METHOD_KEX);
    result.algorithm = algorithm ? algorithm : "";
    const auto fingerprint = reinterpret_cast<const unsigned char *>(
        libssh2_hostkey_hash(client.session, LIBSSH2_HOSTKEY_HASH_SHA256));
    if (!fingerprint || Fingerprint(fingerprint) != options.fingerprint) { result.Fail("Host key mismatch"); return; }
    result.stages.push_back("host-key");
    rc = libssh2_userauth_password_ex(client.session, options.username.c_str(), options.username.size(),
        options.password.c_str(), options.password.size(), nullptr);
    Clear(options.password);
    if (rc != 0) { result.Fail("Authentication failed", rc); return; }
    result.stages.push_back("authenticate");
    if (!Execute(client, result) || !Transfer(client, result)) { return; }
    // 在 SSH 断开前关闭 SFTP 通道，正常路径不依赖断连后的尽力释放。
    rc = libssh2_sftp_shutdown(client.sftp);
    if (rc != 0) { result.Fail("SFTP shutdown failed", rc); return; }
    client.sftp = nullptr;
    rc = libssh2_session_disconnect(client.session, "demo complete");
    if (rc != 0) { result.Fail("SSH disconnect failed", rc); return; }
    result.stages.push_back("disconnect"); result.ok = true;
}

// 异步工作对象由完成回调接管，排队失败时由发起栈释放。
struct Work {
    napi_async_work work = nullptr;
    napi_deferred deferred = nullptr;
    Options options;
    Result result;
};

// 临时 UTF-8 缓冲在复制失败和异常路径同样擦除。
struct SensitiveChars {
    std::vector<char> bytes;
    explicit SensitiveChars(size_t size) : bytes(size, 0) {}
    ~SensitiveChars() {
        volatile char *cursor = bytes.data();
        for (size_t i = 0; i < bytes.size(); ++i) { cursor[i] = 0; }
    }
};

// 校验长度和内嵌 NUL，不能把带尾部数据的参数误当成另一个主机或账号。
bool ReadString(napi_env env, napi_value object, const char *name, std::string &out, size_t maximum)
{
    napi_value value = nullptr; size_t length = 0;
    if (napi_get_named_property(env, object, name, &value) != napi_ok ||
        napi_get_value_string_utf8(env, value, nullptr, 0, &length) != napi_ok || length == 0 || length > maximum) { return false; }
    SensitiveChars temporary(length + 1);
    if (napi_get_value_string_utf8(env, value, temporary.bytes.data(), temporary.bytes.size(), &length) != napi_ok) { return false; }
    out.assign(temporary.bytes.data(), length);
    return out.find(char(0)) == std::string::npos;
}

// 只在 JS 线程创建结果对象，工作线程不访问 NAPI 值。
void Complete(napi_env env, napi_status status, void *data)
{
    std::unique_ptr<Work> work(static_cast<Work *>(data));
    active = false;
    if (status != napi_ok) { work->result.Fail("Cancelled"); }
    napi_value object = nullptr, value = nullptr, stages = nullptr;
    napi_create_object(env, &object);
    napi_get_boolean(env, work->result.ok, &value); napi_set_named_property(env, object, "ok", value);
    napi_create_string_utf8(env, work->result.error.c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, object, "error", value);
    napi_create_string_utf8(env, work->result.algorithm.c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, object, "algorithm", value);
    napi_create_int32(env, work->result.code, &value); napi_set_named_property(env, object, "code", value);
    napi_create_array_with_length(env, work->result.stages.size(), &stages);
    for (size_t i = 0; i < work->result.stages.size(); ++i) {
        napi_create_string_utf8(env, work->result.stages[i].c_str(), NAPI_AUTO_LENGTH, &value);
        napi_set_element(env, stages, i, value);
    }
    napi_set_named_property(env, object, "stages", stages);
    napi_resolve_deferred(env, work->deferred, object);
    napi_delete_async_work(env, work->work);
}

// 校验后才占用运行槽，避免无效请求干扰已有会话。
napi_value StartChecked(napi_env env, napi_callback_info info, bool &ownsSlot)
{
    napi_value args[1] {}, value = nullptr, promise = nullptr, resource = nullptr;
    size_t argc = 1; double port = 0;
    auto work = std::make_unique<Work>();
    if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok || argc != 1 ||
        !ReadString(env, args[0], "host", work->options.host, 253) ||
        !ReadString(env, args[0], "username", work->options.username, 256) ||
        !ReadString(env, args[0], "password", work->options.password, 4096) ||
        !ReadString(env, args[0], "fingerprint", work->options.fingerprint, 64) ||
        !ReadString(env, args[0], "kex", work->options.kex, 128) ||
        napi_get_named_property(env, args[0], "port", &value) != napi_ok ||
        napi_get_value_double(env, value, &port) != napi_ok || !std::isfinite(port) ||
        std::floor(port) != port || port < 1 || port > 65535 ||
        napi_get_named_property(env, args[0], "legacy", &value) != napi_ok ||
        napi_get_value_bool(env, value, &work->options.legacy) != napi_ok) {
        napi_throw_type_error(env, nullptr, "Complete SSH connection options are required"); return nullptr;
    }
    work->options.port = static_cast<uint16_t>(port);
    const std::array<std::string, 8> algorithms {"curve25519-sha256", "diffie-hellman-group14-sha256",
        "diffie-hellman-group16-sha512", "diffie-hellman-group18-sha512", "diffie-hellman-group14-sha1",
        "diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha256", "diffie-hellman-group-exchange-sha1"};
    if (std::find(algorithms.begin(), algorithms.end(), work->options.kex) == algorithms.end() ||
        (!work->options.legacy && work->options.kex.find("sha1") != std::string::npos)) {
        napi_throw_type_error(env, nullptr, "Unsupported KEX or missing legacy opt-in"); return nullptr;
    }
    if (active.exchange(true)) { napi_throw_error(env, nullptr, "A demo run is already active"); return nullptr; }
    ownsSlot = true;
    if (napi_create_string_utf8(env, "Libssh2OhDemo", NAPI_AUTO_LENGTH, &resource) != napi_ok ||
        napi_create_promise(env, &work->deferred, &promise) != napi_ok ||
        napi_create_async_work(env, nullptr, resource, [](napi_env, void *data) {
            auto *item = static_cast<Work *>(data);
            try { Run(item->options, item->result); }
            catch (...) { item->result.Fail("Native failure"); }
        }, Complete, work.get(), &work->work) != napi_ok || napi_queue_async_work(env, work->work) != napi_ok) {
        active = false; ownsSlot = false;
        if (work->work) { napi_delete_async_work(env, work->work); }
        napi_throw_error(env, nullptr, "Cannot queue native demo work"); return nullptr;
    }
    work.release(); ownsSlot = false; return promise;
}

// C++ 分配异常不能穿过 NAPI ABI，且只能归还本请求占用的运行槽。
napi_value Start(napi_env env, napi_callback_info info)
{
    bool ownsSlot = false;
    try { return StartChecked(env, info, ownsSlot); }
    catch (...) {
        if (ownsSlot) { active = false; }
        napi_throw_error(env, nullptr, "Cannot allocate native demo work"); return nullptr;
    }
}

// 模块只导出一个有界的基础流程入口。
napi_value Init(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptor {"run", nullptr, Start, nullptr, nullptr, nullptr, napi_default, nullptr};
    napi_define_properties(env, exports, 1, &descriptor); return exports;
}
} // namespace

static napi_module module {1, 0, nullptr, Init, "ohdemo", nullptr, {0}};
extern "C" __attribute__((constructor)) void RegisterDemo() { napi_module_register(&module); }
