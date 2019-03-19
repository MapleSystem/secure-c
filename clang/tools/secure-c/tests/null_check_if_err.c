//bats @test "null_check_if_err.c: Accessing a nullable pointer in the wrong body of a null-check should report an error" {
//bats   run secure-c null_check_if_err.c --
//bats   [ $status = 1 ]
//bats   [[ ${lines[0]} =~ ":10:12: error: illegal access of nullable pointer type 'int * _Nullable'" ]]
//bats }
#include <stddef.h>

int foo(int * _Nullable x) {
  if (x == NULL) {
    return *x;
  }
  return 0;
}
