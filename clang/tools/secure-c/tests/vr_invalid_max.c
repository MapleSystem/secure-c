char foo(int idx) __attribute__((value_range(idx, 0, 3.14)));

//bats @test "vr_invalid_max.c: Pass an invalid max to value_range attribute" {
//bats   run secure-c vr_invalid_max.c --
//bats   [ $status = 1 ]
//bats   [[ ${lines[0]} =~ ":1:54: error: 'value_range' attribute requires parameter 3 to be an expression of integer type" ]]
//bats }
