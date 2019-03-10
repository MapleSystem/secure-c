int get(int *_Nonnull buf, int len)
    __attribute__((secure_buffer(buf, 10)))
{
  return buf[11];
}

//bats @test "sb_const_outside_const_range.c: Access outside of const secure buffer range with const" {
//bats   run secure-c sb_const_outside_const_range.c --
//bats   [ $status = 1 ]
//bats   [[ ${lines[0]} =~ ":4:14: error: index out of range for secure buffer" ]]
//bats }
