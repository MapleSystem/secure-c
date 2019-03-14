//bats @test "nonnull_param.c: passed to non-null parameter" {
//bats run securify nonnull_param.c --
//bats [ $status = 0 ]
//bats [[ ${lines[7]} =~ "int * _Nonnull x" ]]
//bats }
int foo(int * _Nonnull f);

int bar(int *x) {
  return foo(x);
}
