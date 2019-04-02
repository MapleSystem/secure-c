//bats @test "deref_nullable.c: Dereferencing a nullable pointer should report an error" {
//bats   run secure-c deref_nullable.c --
//bats   [ $status = 1 ]
//bats   [[ ${lines[0]} =~ ":14:10: error: illegal access of nullable pointer type 'int * _Nullable'" ]]
//bats }
//bats @test "deref_nullable.c: insert run-time check on unsafe access" {
//bats   run secure-c -mode=debug deref_nullable.c --
//bats   [ $status = 0 ]
//bats   [[ ${lines[0]} =~ ":14:10: remark: illegal access of nullable pointer type, inserting run-time check" ]]
//bats   [[ ${lines[4]} =~ "#include <secure_c.h>" ]]
//bats   [[ ${lines[18]} =~ "return *((int * _Nonnull)(_CheckNonNull(__FILE__, __LINE__, __extension__ __PRETTY_FUNCTION__, x)));" ]]
//bats }
int foo(int * _Nullable x) {
  return *x;
}
