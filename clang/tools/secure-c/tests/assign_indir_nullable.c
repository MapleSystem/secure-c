//bats @test "assign_indir_nullable.c: Indirectly assigning a nullable value to a pointer after checking for null" {
//bats   skip "Skip until #132 is solved"
//bats   run secure-c assign_indir_nullable.c --
//bats   [ $status != 0 ]
//bats }
#include <stddef.h>

int foo(int * _Nullable p, int *_Nullable q) {
  int * _Nullable * _Nonnull ptr_p = &p;
  if (p != NULL) {
    *ptr_p = q;
    return *p; // Unsafe: p's value was modified after it was null-checked
  }
}
