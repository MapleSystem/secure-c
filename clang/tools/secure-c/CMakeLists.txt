set(LLVM_LINK_COMPONENTS
  Option
  Support
  )

add_clang_tool(secure-c
  SecureC.cpp
  SecureCStatistics.cpp
  NullScope.cpp
  )

target_link_libraries(secure-c
  PRIVATE
  clangAST
  clangBasic
  clangFrontend
  clangLex
  clangRewrite
  clangSecureC
  clangSerialization
  clangTooling
  clangToolingCore
  clangToolingRefactor
  )
