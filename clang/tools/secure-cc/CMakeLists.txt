set(LLVM_LINK_COMPONENTS
  Option
  Support
  )

add_clang_tool(secure-cc
  SecureCC.cpp
  )

target_link_libraries(secure-cc
  PRIVATE
  clangDriver
  clangTooling
  clangToolingCore
  )
