#!/bin/bash

# Ensure securify is in the path
which securify &> /dev/null
if [[ $? -ne 0 ]]; then
  echo -e "\e[01;31merror: securify command not found\e[0m" >&2
  exit 1
fi

# Change to the tests directory
cd "$( dirname "${BASH_SOURCE[0]}" )"

# If no args are passed, test all C files in the tests directory
testcases="$@"
if [[ $# -eq 0 ]]; then
  testcases=*.c
fi

# Collect the bats scripts
OUT="$(mktemp)"
for testcase in $testcases; do
  grep "//bats" "$testcase" | sed 's,^//bats ,,g' >> "$OUT"
done

# Execute the tests
bats "$OUT"
rc=$?

# Remove the temporary file
rm "$OUT"

# Return the result of running the tests
exit $rc
