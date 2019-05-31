//bats @test "null_check_cond_err.c: Dereferencing a known null pointer after a null check" {
//bats   run secure-c null_check_cond_err.c --
//bats   [ $status != 0 ]
//bats }

int foo(int * _Nullable x) {
    if (x) {
        return 0;
    }
    return *x;
}