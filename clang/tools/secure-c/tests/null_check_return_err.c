//bats @test "null_check_return_err.c: Accessing a known-null pointer after a null check with a return should report an error" {
//bats   run secure-c null_check_return_err.c --
//bats   [[ ${lines[0]} =~ ":12:10: error: illegal access of nullable pointer type 'int * _Nullable'" ]]
//bats   [ $status = 1 ]
//bats }
#include <stddef.h>

int foo(int * _Nullable x) {
  if (x != NULL) {
    return 0;
  }
  return *x;
}
