struct {
  int (* _Nonnull f)();
} g;

int foo() {
  return g.f();
}

//bats @test "member_call.c: Call from non-null member function pointer" {
//bats   run secure-c member_call.c --
//bats   [ $status = 0 ]
//bats }
//bats @test "member_call.c: Statistics: Call from non-null member function pointer" {
//bats   run secure-c -dump-stats member_call.c --
//bats   [ $status = 0 ]
//bats   [[ ${lines[5]} =~ "Function calls:  1" ]]
//bats   [[ ${lines[10]} =~ "Safe by annotation: 1" ]]
//bats }
