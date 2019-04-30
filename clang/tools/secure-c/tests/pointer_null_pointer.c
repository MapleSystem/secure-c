#include <stddef.h>

int *_Nullable foo(int * _Nonnull * _Nonnull p) {
  int * _Nonnull * _Nullable q = p; // Conversion to _Nullable is safe
  if (q != NULL) return *q;
  return NULL;
}

//bats @test "pointer_null_pointer.c: Checked cast allows removing the nonnull attribute of a pointer value" {
//bats   run secure-c pointer_null_pointer.c --
//bats   [ $status = 0 ]
//bats }
