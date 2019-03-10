int get(int idx, int *_Nonnull buf, int len) {
  return buf[idx];
}

//bats @test "sb_missing_disabled.c: Access pointer without secure_buffer annotation with check disabled" {
//bats   run secure-c -secure-buffer=false sb_missing_disabled.c --
//bats   [ $status = 0 ]
//bats }
