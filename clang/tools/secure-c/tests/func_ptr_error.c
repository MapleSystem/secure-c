//bats @test "func_ptr_error.c: Call a nullable function pointer" {
//bats   run secure-c func_ptr_error.c --
//bats   [ $status = 1 ] && echo ${lines[0]}
//bats   [[ ${lines[0]} =~ ":8:10: error: illegal access of nullable pointer type 'int (*)()'" ]]
//bats }
int foo() {
  int (*funcPtr)();
  return funcPtr();
}
