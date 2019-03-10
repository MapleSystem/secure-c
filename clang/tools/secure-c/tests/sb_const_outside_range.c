int get(int *_Nonnull buf, int len)
    __attribute__((secure_buffer(buf, len)))
{
  return buf[11];
}

//bats @test "sb_const_outside_range.c: Access outside of secure buffer range with const" {
//bats   run secure-c sb_const_outside_range.c --
//bats   [ $status = 1 ]
//bats   [[ ${lines[0]} =~ ":4:14: error: unable to guarantee that index is within range of secure buffer" ]]
//bats }
