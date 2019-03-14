//bats @test "init_with_nonnull.c: initialize with non-null" {
//bats run securify init_with_nonnull.c --
//bats [ $status = 0 ]
//bats [[ ${lines[7]} =~ "int * _Nonnull x" ]]
//bats }
int foo(int * _Nonnull a) {
  int *x = a;
  return *x;
}
