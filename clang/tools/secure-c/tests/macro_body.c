//bats @test "macro_body.c: Insert check into macro body (not arg)" {
//bats   run secure-c -mode=debug macro_body.c --
//bats   [ $status = 0 ] && echo ${lines[16]}
//bats   [[ ${lines[0]} =~ ":13:10: remark: illegal access of nullable pointer type, inserting run-time check" ]]
//bats   [[ ${lines[7]} =~ "#include <secure_c.h>" ]]
//bats   [[ ${lines[16]} =~ "#define GET(N) (((int * _Nonnull)(_CheckNonNull(__FILE__, __LINE__, __extension__ __PRETTY_FUNCTION__, gArray)))[N])" ]]
//bats }
int *gArray;

#define GET(N) (gArray[N])

int foo(int i) {
  return GET(i);
}
