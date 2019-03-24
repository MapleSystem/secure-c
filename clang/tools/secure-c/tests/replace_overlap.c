//bats @test "replace_overlap.c: handle overlapping replacements" {
//bats   run secure-c -mode=debug replace_overlap.c --
//bats   [ $status = 0 ]
//bats   [[ ${lines[18]} =~ "return (struct S * _Nonnull)(_CheckNonNull(__FILE__, __LINE__, __extension__ __PRETTY_FUNCTION__, (struct S * _Nonnull)(_CheckNonNull(__FILE__, __LINE__, __extension__ __PRETTY_FUNCTION__, s))->s))->i;" ]]
//bats }
struct S {
  struct S *s;
  int i;
};

int foo(struct S * _Nullable s) {
  return s->s->i;
}
