#include <stddef.h>

int * _Nullable foo_n_n(int * _Nullable * _Nullable p) {
  if (p == NULL) return NULL;
  return *p;
}

int foo_n_nn(int * _Nullable * _Nullable p) {
  if (p == NULL) return 0;
  if (*p == NULL) return 0;
  return **p;
}

//bats @test "pointer_pointer_check.c: Accessing a pointer to a pointer (checked)" {
//bats   skip "Skip until #86 is fixed"
//bats   run secure-c pointer_pointer_check.c --
//bats   [ $status = 0 ]
//bats }
