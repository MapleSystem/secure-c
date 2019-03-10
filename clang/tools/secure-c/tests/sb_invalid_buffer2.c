int * _Nonnull g;

int get(int *_Nonnull buf, int len)
    __attribute__((secure_buffer(g, len)))
{
  return buf[0];
}

//bats @test "sb_invalid_buffer2.c: Pass an invalid buffer to secure_buffer attribute" {
//bats   run secure-c sb_invalid_buffer2.c --
//bats   [ $status = 1 ]
//bats   [[ ${lines[0]} =~ ":4:34: error: 'secure_buffer' attribute requires parameter 1 to be a function parameter of pointer type" ]]
//bats }
