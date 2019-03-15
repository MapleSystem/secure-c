//bats @test "cg_order.c: call-graph order dependent analysis" {
//bats run securify cg_order.c --
//bats [ $status = 0 ]
//bats [[ ${lines[8]} =~ "foo(int * _Nonnull a)" ]]
//bats [[ ${lines[10]} =~ "bar(int * _Nonnull x)" ]]
//bats [[ ${lines[14]} =~ "foo(int * _Nonnull a)" ]]
//bats }
int foo(int *a);

int bar(int *x) {
  return foo(x);
}

int foo(int *a) {
  return *a;
}
