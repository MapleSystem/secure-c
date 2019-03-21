//bats @test "func_ptr.c: annotate function pointers" {
//bats run securify func_ptr.c --
//bats [ $status = 0 ]
//bats [[ ${lines[8]} =~ "int (* _Nonnull funcPtr)()" ]]
//bats }
int bar() { return 3; }

int foo() {
  int (*funcPtr)() = bar;
  return funcPtr();
}
