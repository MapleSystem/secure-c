struct {
  int (*f)();
} g;

int foo() {
  return g.f();
}

//bats @test "member_call_error.c: Call from nullable member function pointer" {
//bats   run secure-c member_call_error.c --
//bats   [ $status = 1 ]
//bats   [[ ${lines[0]} =~ ":6:10: error: illegal access of nullable pointer type 'int (*)()'" ]]
//bats }
