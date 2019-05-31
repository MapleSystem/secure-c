set(LLVM_LINK_COMPONENTS
  Option
  Support
  )

add_clang_tool(securify
  Securify.cpp
  )

target_link_libraries(securify
  PRIVATE
  clangAST
  clangASTMatchers
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
