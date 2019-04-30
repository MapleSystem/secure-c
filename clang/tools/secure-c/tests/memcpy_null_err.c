//bats @test "memcpy_null_err.c: Using memcpy to coerce a _Nullable pointer to a _Nonnull pointer" {
//bats   run secure-c memcpy_null_err.c --
//bats   [ $status != 0 ]
//bats }
#include <stddef.h>
#include <string.h>

void foo(int *_Nonnull *_Nonnull p, int *_Nullable *_Nonnull q) {
  memcpy(p, q, sizeof(int *)); // Unsafe: writes a null pointer value
}
