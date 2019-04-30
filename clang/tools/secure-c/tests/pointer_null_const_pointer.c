#include <stddef.h>

int * const _Nullable * _Nonnull foo(int * _Nonnull * _Nonnull p) {
  int * const _Nullable * _Nonnull q = p; // Conversion to pointer-to-const-nullable is safe
  return q;
}

int bar(void) {
  int x = 100;
  int *_Nonnull ptr_x = &x;
  int *const _Nullable y = *foo(&ptr_x);
  if (y != NULL) return *y;
}

//bats @test "pointer_null_const_pointer.c: Casting from nonnull to const nullable pointer type" {
//bats   run secure-c pointer_null_const_pointer.c --
//bats   [ $status = 0 ]
//bats }
