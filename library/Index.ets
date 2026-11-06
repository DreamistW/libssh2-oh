// ArkTS 入口只导出版本信息；SSH 公共接口由 libssh2.h 提供。
export const LIBSSH2_OH_VERSION: string = '0.1.1';
// 上游基础版本不包含移植修订号，补丁清单见包内 manifest。
export const LIBSSH2_UPSTREAM_VERSION: string = '1.11.1';
