//bats @test "replace_overlap_offset.c: handle overlapping replacements" {
//bats   run secure-c -mode=debug replace_overlap_offset.c --
//bats   [ $status = 0 ]
//bats   [[ ${lines[17]} =~ "*((unsigned int * _Nonnull)(_CheckNonNull(__FILE__, __LINE__, __extension__ __PRETTY_FUNCTION__, (unsigned int *)((struct S * _Nonnull)(_CheckNonNull(__FILE__, __LINE__, __extension__ __PRETTY_FUNCTION__, s))->i))));" ]]
//bats }
struct S {
  int *i;
};

unsigned int foo(struct S * _Nullable s) {
  return *((unsigned int *)(s->i));
}
