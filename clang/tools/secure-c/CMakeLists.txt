set(LLVM_LINK_COMPONENTS
  Option
  Support
  )

add_clang_tool(secure-c
  SecureC.cpp
  )

target_link_libraries(secure-c
  PRIVATE
  clangBasic
  clangFrontend
  clangRewrite
  clangSerialization
  clangTooling
  clangToolingCore
  clangToolingRefactor
  )
