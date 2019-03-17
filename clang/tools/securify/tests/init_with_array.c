//bats @test "init_with_array.c: initialize with an array" {
//bats run securify init_with_array.c --
//bats [ $status = 0 ]
//bats [[ ${lines[8]} =~ "int * _Nonnull x" ]]
//bats }
int a[3];
int foo() {
  int *x = a;
  return *x;
}
