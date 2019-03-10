int get(int x, int *_Nonnull buf, int len)
    __attribute__((secure_buffer(buf, len)))
{
  return buf[x + 2];
}

//bats @test "sb_expr_outside_range.c: Access outside of secure buffer range with expression" {
//bats   run secure-c sb_expr_outside_range.c --
//bats   [ $status = 1 ]
//bats   [[ ${lines[0]} =~ ":4:14: error: unable to guarantee that index is within range of secure buffer" ]]
//bats }
