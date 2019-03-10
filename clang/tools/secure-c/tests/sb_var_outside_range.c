int get(int x, int *_Nonnull buf, int len)
    __attribute__((secure_buffer(buf, len)))
{
  int idx = x + 2;
  return buf[idx];
}

//bats @test "sb_var_outside_range.c: Access outside of secure buffer range with variable" {
//bats   run secure-c sb_var_outside_range.c --
//bats   [ $status = 1 ]
//bats   [[ ${lines[0]} =~ ":5:14: error: unable to guarantee that index is within range of secure buffer" ]]
//bats }
