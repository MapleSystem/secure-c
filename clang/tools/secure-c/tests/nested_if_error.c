//bats @test "nested_if_error.c: Check pointers in nested if-statements" {
//bats   run secure-c nested_if_error.c --
//bats   [ $status = 1 ]
//bats   [[ ${lines[0]} =~ ":12:7: error: illegal access of nullable pointer type 'int * _Nullable'" ]]
//bats }

int bar(int* _Nullable p, int* _Nullable q) {
  if (p != 0) {
    if (q != 0) {
		return 0;
	}
	*p = *q;
  }
  return 0;
}
