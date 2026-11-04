cmake_minimum_required(VERSION 3.16)
project(libssh2_oh_demo CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(DEFINED LIBSSH2_OH_NATIVE_PREFIX)
  # 仅用于原生构建机编译检查；本机 HAP 默认走下面的实际 HAR 依赖。
  add_library(libssh2-oh::ssh2 STATIC IMPORTED)
  set_target_properties(libssh2-oh::ssh2 PROPERTIES
    IMPORTED_LOCATION "${LIBSSH2_OH_NATIVE_PREFIX}/lib/libssh2.a"
    INTERFACE_INCLUDE_DIRECTORIES "${LIBSSH2_OH_NATIVE_PREFIX}/include"
    INTERFACE_LINK_LIBRARIES "libohcrypto.so;libhilog_ndk.z.so")
else()
  set(_oh_package "${CMAKE_CURRENT_SOURCE_DIR}/../../../oh_modules/libssh2-oh")
  if(NOT EXISTS "${_oh_package}/include/libssh2-oh.cmake")
    set(_oh_package "${CMAKE_CURRENT_SOURCE_DIR}/../../../../oh_modules/libssh2-oh")
  endif()
  include("${_oh_package}/include/libssh2-oh.cmake")
endif()

add_library(ohdemo SHARED napi_init.cpp)
target_compile_options(ohdemo PRIVATE -Wall -Wextra -Werror -Wno-error=unused-command-line-argument
  -fstack-protector-strong)
target_link_libraries(ohdemo PRIVATE libssh2-oh::ssh2 libace_napi.z.so)
