#!/bin/bash

which securify &> /dev/null
if [[ $? -ne 0 ]]; then
  echo -e "\e[01;31merror: securify command not found\e[0m" >&2
  exit 1
fi
OUT="$(mktemp)"
for testcase in "$@"; do
  grep "//bats" "$testcase" | sed 's,^//bats ,,g' >> "$OUT"
done
bats "$OUT"
rm "$OUT"

