#include <stddef.h>

void foo(int * _Nonnull * _Nonnull p) {
  int * _Nullable * _Nonnull q = p; // Conversion to pointer-to-nullable is unsafe
  *q = NULL;
}

void crashes(void) {
  int x = 100;
  int *_Nonnull ptr_x = &x;
  foo(&ptr_x);
  int y = *ptr_x; // null dereference
}

//bats @test "pointer_null_pointer_err.c: Casting from nonnull to nullable pointer type is prohibited" {
//bats   skip "Skip until #136 is solved"
//bats   run secure-c pointer_null_pointer_err.c --
//bats   [ $status != 0 ]
//bats }
