// RUN: %clangxx_asan -fsanitize-coverage=func,trace-pc-guard -DSHARED %s -shared -o %dynamiclib -fPIC %ld_flags_rpath_so
// RUN: %clangxx_asan -fsanitize-coverage=func,trace-pc-guard %s %ld_flags_rpath_exe -o %t
// RUN: rm -rf %T/coverage-reset && mkdir -p %T/coverage-reset && cd %T/coverage-reset
// RUN: %env_asan_opts=coverage=1:verbosity=1 %run %t 2>&1 | FileCheck %s
//
// UNSUPPORTED: ios

#include <stdio.h>

#include <sanitizer/coverage_interface.h>

#ifdef SHARED
void bar1() { printf("bar1\n"); }
void bar2() { printf("bar2\n"); }
#else
__attribute__((noinline)) void foo1() { printf("foo1\n"); }
__attribute__((noinline)) void foo2() { printf("foo2\n"); }
void bar1();
void bar2();

int main(int argc, char **argv) {
  fprintf(stderr, "RESET");
  __sanitizer_cov_reset();
  foo1();
  foo2();
  bar1();
  bar2();
  __sanitizer_cov_dump();
// CHECK: RESET
// CHECK: SanitizerCoverage: ./coverage-reset.cc{{.*}}.sancov: 2 PCs written
// CHECK: SanitizerCoverage: ./libcoverage-reset.cc{{.*}}.sancov: 2 PCs written

  fprintf(stderr, "RESET");
  __sanitizer_cov_reset();
  foo1();
  bar1();
  __sanitizer_cov_dump();
// CHECK: RESET
// CHECK: SanitizerCoverage: ./coverage-reset.cc{{.*}}.sancov: 1 PCs written
// CHECK: SanitizerCoverage: ./libcoverage-reset.cc{{.*}}.sancov: 1 PCs written

  fprintf(stderr, "RESET");
  __sanitizer_cov_reset();
  foo1();
  foo2();
  __sanitizer_cov_dump();
// CHECK: RESET
// CHECK: SanitizerCoverage: ./coverage-reset.cc{{.*}}.sancov: 2 PCs written

  fprintf(stderr, "RESET");
  __sanitizer_cov_reset();
  bar1();
  bar2();
  __sanitizer_cov_dump();
// CHECK: RESET
// CHECK: SanitizerCoverage: ./libcoverage-reset.cc{{.*}}.sancov: 2 PCs written

  fprintf(stderr, "RESET");
  __sanitizer_cov_reset();
// CHECK: RESET

  bar2();
// CHECK: SanitizerCoverage: ./libcoverage-reset.cc{{.*}}.sancov: 1 PCs written
}
#endif
