#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 <path>"
  exit 1
fi

php -d extension=posix ai-bolit-hoster.php --report=ai-bolit.html --smart --deobfuscate --with-suspicious --cloud-assist=AUTO --avdb=sigs/aibolit/ai-bolit-hoster-full.db --use-heuristics-ignore "$1"
