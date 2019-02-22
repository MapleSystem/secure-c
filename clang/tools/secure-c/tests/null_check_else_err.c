//bats @test "null_check_else_err.c: Accessing a nullable pointer in the wrong body of a null-check should report an error" {
//bats   run secure-c null_check_else_err.c --
//bats   [[ ${lines[0]} =~ ":12:12: error: illegal access of nullable pointer type 'int * _Nullable'" ]]
//bats   [ $status = 1 ]
//bats }
#include <stddef.h>

int foo(int * _Nullable x) {
  if (x != NULL) {
    return 0;
  } else {
    return *x;
  }
}
