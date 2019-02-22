//bats @test "cast_error.c: Assigning a nullable pointer to a non-null pointer should report an error" {
//bats   run secure-c cast_error.c --
//bats   [[ ${lines[0]} =~ ":13:7: error: implicit conversion from nullable pointer type 'int *' to non-nullable pointer type 'int * _Nonnull'" ]]
//bats   [ $status = 1 ]
//bats }
#include <stddef.h>

int gX;

int foo() {
  int * _Nonnull a = &gX;
  int * b = NULL;
  a = b;
  return 0;
}
