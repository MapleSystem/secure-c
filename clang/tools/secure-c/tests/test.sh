#!/bin/bash

OUT="$(mktemp)"
for testcase in "$@"; do
  grep "//bats" "$testcase" | sed 's,^//bats ,,g' >> "$OUT"
done
bats "$OUT"
rm "$OUT"

