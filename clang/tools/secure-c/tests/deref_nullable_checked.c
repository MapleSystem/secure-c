//bats @test "deref_nullable_checked.c: verify that the inserted check works to avoid an error" {
//bats   run secure-c deref_nullable_checked.c -- -I../
//bats   [ $status = 0 ]
//bats }
#include <secure_c.h>

int foo(int * _Nullable x) {
  return *(int * _Nonnull)(_CheckNonNull(__FILE__, __LINE__, __extension__ __PRETTY_FUNCTION__, x));
}
