//bats @test "nonnull_assign.c: assign to non-null variable" {
//bats run securify nonnull_assign.c --
//bats [ $status = 0 ]
//bats [[ ${lines[7]} =~ "int * _Nonnull x" ]]
//bats }
int * _Nonnull f;

void bar(int *x) {
  f = x;
}
