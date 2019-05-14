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
  clangBasic
  clangFrontend
  clangRewrite
  clangSerialization
  clangTooling
  clangToolingCore
  clangToolingRefactor
  )
