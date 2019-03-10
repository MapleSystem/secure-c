int get(int *_Nonnull buf, int len)
    __attribute__((secure_buffer(buf, 10)))
{
  return buf[1];
}

//bats @test "sb_const_within_range.c: Access within secure buffer range" {
//bats   run secure-c sb_const_within_range.c --
//bats   [ $status = 0 ]
//bats }
