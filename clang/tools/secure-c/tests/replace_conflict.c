//bats @test "replace_conflict.c: Insert duplicate check into macro" {
//bats   run secure-c -mode=debug replace_conflict.c --
//bats   [ $status = 0 ]
//bats   [[ ${lines[43]} =~ "#define DOIT(S) (*(((unsigned int * _Nonnull)(_CheckNonNull(__FILE__, __LINE__, __extension__ __PRETTY_FUNCTION__, ((unsigned int * _Nonnull)(_CheckNonNull(__FILE__, __LINE__, __extension__ __PRETTY_FUNCTION__, (unsigned int*)(((struct Stream * _Nonnull)(_CheckNonNull(__FILE__, __LINE__, __extension__ __PRETTY_FUNCTION__, S->strm)))->next_in)))))))))" ]]
//bats }
struct Stream {
  int *next_in;
};

struct S {
  struct Stream *strm;
};

#define DOIT(S) (*((unsigned int*)(S->strm->next_in)))

unsigned int foo(struct S * _Nonnull s1, struct S * _Nullable s2) {
  DOIT(s1);
  return DOIT(s2);
}
