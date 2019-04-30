//bats @test "memcpy_1.c: Using memcpy to copy a _Nullable pointer safely" {
//bats   run secure-c memcpy_1.c --
//bats   [ $status = 0 ]
//bats }
#include <stddef.h>
#include <string.h>

void foo(int *_Nullable *_Nonnull p, int *_Nullable *_Nonnull q) {
  memcpy(p, q, sizeof(int *)); // Safe: both pointers have same type
}
