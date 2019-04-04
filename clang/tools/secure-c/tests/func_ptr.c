//bats @test "func_ptr.c: Calling a function pointer" {
//bats   run secure-c func_ptr.c --
//bats   [ $status = 0 ]
//bats }

int bar(void) {
  return 42;
}

int foo() {
  int (* funcPtr)(void);
  funcPtr = bar;
  return funcPtr();
}

//bats @test "func_ptr.c: Statistics: Calling a function pointer" {
//bats   run secure-c -dump-stats func_ptr.c --
//bats   [ $status = 0 ]
//bats   [[ ${lines[5]} =~ "Function calls:  1"$ ]]
//bats   [[ ${lines[11]} =~ "Safe by analysis:   1"$ ]]
//bats }
