set(LLVM_LINK_COMPONENTS
  Option
  Support
  )

add_clang_tool(securify-cc
  SecurifyCC.cpp
  )

target_link_libraries(securify-cc
  PRIVATE
  clangTooling
  clangToolingCore
  )
