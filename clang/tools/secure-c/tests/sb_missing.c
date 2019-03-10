int get(int idx, int *_Nonnull buf, int len) {
  return buf[idx];
}

//bats @test "sb_missing.c: Access pointer without secure_buffer annotation" {
//bats   run secure-c sb_missing.c --
//bats   [ $status = 1 ]
//bats   [[ ${lines[0]} =~ ":2:10: error: illegal access of pointer without secure_buffer attribute" ]]
//bats }
