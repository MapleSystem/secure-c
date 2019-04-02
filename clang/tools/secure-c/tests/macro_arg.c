//bats @test "macro_arg.c: Insert check into argument to macro" {
//bats   run secure-c -mode=debug macro_arg.c --
//bats   [ $status = 0 ] && echo ${lines[20]}
//bats   [[ ${lines[0]} =~ ":15:14: remark: illegal access of nullable pointer type, inserting run-time check" ]]
//bats   [[ ${lines[7]} =~ "#include <secure_c.h>" ]]
//bats   [[ ${lines[20]} =~ "GET(((struct Stream * _Nonnull)(_CheckNonNull(__FILE__, __LINE__, __extension__ __PRETTY_FUNCTION__, s)))->next_in)" ]]
//bats }
struct Stream {
  int next_in;
};

#define GET(X) (X + 1)

unsigned int foo(struct Stream * _Nullable s) {
  return GET(s->next_in);
}
