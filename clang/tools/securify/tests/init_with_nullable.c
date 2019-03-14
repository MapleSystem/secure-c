//bats @test "init_with_nullable.c: initialize with nullable" {
//bats run securify init_with_nullable.c --
//bats [ $status = 0 ]
//bats [[ ${lines[7]} =~ "int * _Nullable x" ]]
//bats }
int foo(int * _Nullable a) {
  int *x = a;
  return *x;
}
