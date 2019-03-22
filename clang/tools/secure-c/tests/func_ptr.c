//bats @test "func_ptr.c: Calling a function pointer" {
//bats   run secure-c func_ptr.c --
//bats   [ $status = 0 ]
//bats }
int bar() {
  return 42;
}

int foo() {
  int (* funcPtr)();
  funcPtr = bar;
  return funcPtr();
}
