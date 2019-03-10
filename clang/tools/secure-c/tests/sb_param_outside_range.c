int get(int idx, int *_Nonnull buf, int len)
    __attribute__((secure_buffer(buf, len)))
{
  return buf[idx];
}

//bats @test "sb_param_outside_range.c: Access outside of secure buffer range with param" {
//bats   run secure-c sb_param_outside_range.c --
//bats   [ $status = 1 ]
//bats   [[ ${lines[0]} =~ ":4:14: error: unable to guarantee that index is within range of secure buffer" ]]
//bats }
