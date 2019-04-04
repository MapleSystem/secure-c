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

//bats @test "member_nonnull.c: Statistics: Accessing a member of a non-null pointer" {
//bats   run secure-c -dump-stats member_nonnull.c --
//bats   [ $status = 0 ]
//bats   [[ ${lines[6]} =~ "Member accesses: 1"$ ]]
//bats   [[ ${lines[10]} =~ "Safe by annotation: 1"$ ]]
//bats }
