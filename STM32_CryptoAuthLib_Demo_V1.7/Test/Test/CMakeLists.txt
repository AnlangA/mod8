# CMakeList.txt: Test 的 CMake 项目，在此处包括源代码并定义
# 项目特定的逻辑。
#
cmake_minimum_required (VERSION 3.8)

# openssl
# window:libcrypto.lib linux:libssl-dev
find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
  include_directories(${OPENSSL_INCLUDE_DIRS})
  message(STATUS "OpenSSL Found!")
endif()



# 将源代码添加到此项目的可执行文件。
add_executable (Test "Test.cpp" "Test.h" "../../CryptoAuthLib/crypto/mse_crypto_sw_sha2.c" "../../CryptoAuthLib/crypto/mse_crypto_sw_sha2.h" "../../CryptoAuthLib/openssl/openssl_interface.c" "../../CryptoAuthLib/crypto/hashes/sha2_routines.c")
target_link_libraries(Test OpenSSL::Crypto)

# TODO: 如有需要，请添加测试并安装目标。
