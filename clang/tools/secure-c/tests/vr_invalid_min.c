char foo(int idx, int *p) __attribute__((value_range(idx, p, 26)));

//bats @test "vr_invalid_min.c: Pass an invalid min to value_range attribute" {
//bats   run secure-c vr_invalid_min.c --
//bats   [ $status = 1 ]
//bats   [[ ${lines[0]} =~ ":1:59: error: 'value_range' attribute requires parameter 2 to be an expression of integer type" ]]
//bats }
