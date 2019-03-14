//bats @test "deref.c: unprotected dereference" {
//bats run securify deref.c --
//bats [ $status = 0 ]
//bats [[ ${lines[6]} =~ "int * _Nonnull f" ]]
//bats }
int foo(int *f) {
  return *f + 1;
}
