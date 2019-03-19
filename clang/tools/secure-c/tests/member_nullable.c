//bats @test "member_nullable.c: Accessing a member of a nullable pointer should report an error" {
//bats   run secure-c member_nullable.c --
//bats   [ $status = 1 ]
//bats   [[ ${lines[0]} =~ ":12:10: error: illegal access of nullable pointer type 'foo * _Nullable'" ]]
//bats }
typedef struct {
  int count;
  int val;
} foo;

int get_count(foo * _Nullable f) {
  return f->count;
}
