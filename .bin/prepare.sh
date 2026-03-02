#!/bin/bash

message="$(date '+%Y/%m/%d %H:%M')"
echo "$message"

BASE=$(git merge-base HEAD origin/main)

git reset "$BASE"

git add -A

git commit -m "$message"