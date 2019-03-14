//bats @test "init_with_addrof.c: initialize with the address of a variable" {
//bats run securify init_with_addrof.c --
//bats [ $status = 0 ]
//bats [[ ${lines[7]} =~ "int * _Nonnull x" ]]
//bats }
int foo(int a) {
  int *x = &a;
  return *x;
}
