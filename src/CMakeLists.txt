include_directories(.)

# 测试程序
add_executable(
  test

  test.cpp
)
target_link_libraries(
  test

  snark
)
target_include_directories(
  test

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)

# SHA256 gadget
add_executable(
  sha256_gadget_test

  sha256_gadget_test.cpp
)
target_link_libraries(
  sha256_gadget_test

  snark
)
target_include_directories(
  sha256_gadget_test

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)

# 关闭调试模式，否则gadget输入不满足约束会直接exit
option(
  DEBUG
  "Enable debugging mode"
  OFF
)