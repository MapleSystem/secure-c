//bats @test "call_error.c: Passing a nullable pointer to a non-null parameter should report an error" {
//bats   run secure-c call_error.c --
//bats   [ $status = 1 ]
//bats   [[ ${lines[0]} =~ ":12:7: error: unsafe promotion from nullable pointer type 'int *' to non-nullable pointer type 'int * _Nonnull'" ]]
//bats }
#include <stddef.h>

void foo(int * _Nonnull ptr);

void bar() {
  int *x = NULL;
  foo(x);
}
