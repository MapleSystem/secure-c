int get(int *_Nonnull buf, char * _Nullable len)
    __attribute__((secure_buffer(buf, len)))
{
  return buf[0];
}

//bats @test "sb_invalid_length.c: Pass an invalid length to secure_buffer attribute" {
//bats   run secure-c sb_invalid_length.c --
//bats   [ $status = 1 ]
//bats   [[ ${lines[0]} =~ ":2:39: error: 'secure_buffer' attribute requires parameter 2 to be an expression of integer type" ]]
//bats }
