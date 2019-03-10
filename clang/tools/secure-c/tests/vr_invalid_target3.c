char foo(int *buf) __attribute__((value_range(buf, 0, 26)));

//bats @test "vr_invalid_target3.c: Pass an invalid target to value_range attribute" {
//bats   run secure-c vr_invalid_target3.c --
//bats   [ $status = 1 ]
//bats   [[ ${lines[0]} =~ ":1:47: error: 'value_range' attribute requires parameter 1 to be a function parameter of integer type" ]]
//bats }
