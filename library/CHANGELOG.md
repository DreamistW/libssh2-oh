# 更新记录

## 0.1.0 — 2026-11-05

- 基于 libssh2 1.11.1 与锁定安全补丁构建 HarmonyOS 静态库。
- 原创 OHCRYPTO 后端动态调用系统 libohcrypto.so。
- DH 按实际 p/g 生成和导入密钥，支持固定组及 Group Exchange。
- 导出公共 C 头文件、静态库及 CMake 导入目标。
- 提供原生库、HAR 和独立 demo 的构建脚本。
- 构建强制检查输入、缓存内容和产物来源，保留完整许可。
- 支持范围为 API 26、arm64-v8a、2in1。
