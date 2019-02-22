//bats @test "member_nonnull.c: Accessing a member of a non-null parameter" {
//bats   run secure-c member_nonnull.c --
//bats   [ $status = 0 ]
//bats }
typedef struct {
  int count;
  int val;
} foo;

int get_count(foo * _Nonnull f) {
  return f->count;
}
