set(LLVM_LINK_COMPONENTS
  Support
  )

add_clang_library(clangSecureC
  KnownSymbols.cpp

  LINK_LIBS
  clangAST
  clangBasic
  )
