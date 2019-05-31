//bats @test "null_check_cond.c: Dereferencing a nullable pointer after a null check" {
//bats   run secure-c null_check_cond.c --
//bats   [ $status = 0 ]
//bats }

int foo(int * _Nullable x) {
    if (!x) {
        return 0;
    }
    return *x;
}