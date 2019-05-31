//bats @test "null_check_ternary_err.c: Dereferencing a known null pointer after a null check" {
//bats   run secure-c null_check_ternary_err.c --
//bats   [ $status != 0 ]
//bats }
#include <stddef.h>
int foo(int * _Nullable x, int * _Nonnull y) {
    return ((x == NULL) ? (*x > 0) : (*y == 0));
}