//bats @test "deref_nullable.c: Dereferencing a nullable pointer should report an error" {
//bats   run secure-c deref_nullable.c --
//bats   [ $status = 1 ]
//bats   [[ ${lines[0]} =~ ":7:10: error: illegal access of nullable pointer type 'int * _Nullable'" ]]
//bats }
int foo(int * _Nullable x) {
  return *x;
}
