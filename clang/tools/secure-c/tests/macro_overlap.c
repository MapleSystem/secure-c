//bats @test "macro_overlap.c: Insert overlapping checks into macro" {
//bats   run secure-c -mode=debug macro.c --
//bats   [ $status = 0 ] && echo ${lines[21]}
//bats   [[ ${lines[0]} =~ ":19:14: remark: illegal access of nullable pointer type, inserting run-time check" ]]
//bats   [[ ${lines[7]} =~ "#include <secure_c.h>" ]]
//bats   [[ ${lines[21]} =~ "#define GET(P) (((struct Stream * _Nonnull)(_CheckNonNull(__FILE__, __LINE__, __extension__ __PRETTY_FUNCTION__, P->strm)))->next_in)" ]]

//bats   [ $status = 0 ]
//bats   [[ ${lines[0]} =~ ":19:14: remark: illegal access of nullable pointer type, inserting run-time check" ]]
//bats   [[ ${lines[7]} =~ "#include <secure_c.h>" ]]
//bats   [[ ${lines[21]} =~ "#define GET(P) (((struct Stream * _Nonnull)(_CheckNonNull(__FILE__, __LINE__, __extension__ __PRETTY_FUNCTION__, P->strm)))->next_in)" ]]
//bats }
struct Stream {
  int *next_in;
};

struct S {
  struct Stream *strm;
};

#define GET(P) (*(P->strm->next_in))

unsigned int foo(struct S * _Nonnull s) {
  return GET(s);
}
