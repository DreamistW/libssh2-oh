# 将 HAR 内的静态 libssh2 及系统密码学依赖一起交给消费者。
if(TARGET libssh2-oh::ssh2)
  return()
endif()

if(NOT OHOS_ARCH STREQUAL "arm64-v8a")
  message(FATAL_ERROR "libssh2-oh 0.1.1 supports arm64-v8a only")
endif()

get_filename_component(_libssh2_oh_root "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
set(_libssh2_oh_archive "${_libssh2_oh_root}/libs/${OHOS_ARCH}/libssh2.a")
if(NOT EXISTS "${_libssh2_oh_archive}")
  message(FATAL_ERROR "Missing libssh2-oh static archive: ${_libssh2_oh_archive}")
endif()

add_library(libssh2-oh::ssh2 STATIC IMPORTED GLOBAL)
set_target_properties(libssh2-oh::ssh2 PROPERTIES
  IMPORTED_LOCATION "${_libssh2_oh_archive}"
  INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_LIST_DIR}"
  INTERFACE_LINK_LIBRARIES "libohcrypto.so;libhilog_ndk.z.so"
)
unset(_libssh2_oh_archive)
unset(_libssh2_oh_root)
