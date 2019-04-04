int foo() {
  int (*funcPtr)();
  return funcPtr();
}

//bats @test "func_ptr_error.c: Call a nullable function pointer" {
//bats   run secure-c func_ptr_error.c --
//bats   [ $status = 1 ]
//bats   [[ ${lines[0]} =~ ":3:10: error: illegal access of nullable pointer type 'int (*)()'" ]]
//bats }
//bats @test "func_ptr_error.c: Null-check inserted for function pointer" {
//bats   run secure-c -mode=debug func_ptr_error.c --
//bats   [ $status = 0 ]
//bats   [[ ${lines[7]} =~ "  return ((int (* _Nonnull)())(_CheckNonNull(__FILE__, __LINE__, __extension__ __PRETTY_FUNCTION__, funcPtr)))();" ]]
//bats }
