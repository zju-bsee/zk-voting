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

# # 选民身份证明测试gadget
# add_executable(
#   identity_fake_gadget

#   identity_fake_test.cpp
# )
# target_link_libraries(
#   identity_fake_gadget

#   snark
# )
# target_include_directories(
#   identity_fake_gadget

#   PUBLIC
#   ${DEPENDS_DIR}/libsnark
#   ${DEPENDS_DIR}/libsnark/depends/libfqfft
#   ${DEPENDS_DIR}/libsnark/depends/libff
# )

# 选民身份证明测试动态链接库
add_library(
  zkvoting SHARED

  jni.cpp
)
target_link_libraries(
  zkvoting

  snark
)
target_include_directories(
  zkvoting

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