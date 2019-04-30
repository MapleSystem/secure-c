//bats @test "assign_nullable.c: Assigning a nullable value to a pointer after checking for null" {
//bats   run secure-c assign_nullable.c --
//bats   [ $status != 0 ]
//bats }
#include <stddef.h>

int foo(int * _Nullable p, int *_Nullable q) {
  if (p != NULL) {
    p = q;
    return *p; // Unsafe: p's value was modified after it was null-checked
  }
}
