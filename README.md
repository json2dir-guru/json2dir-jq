# json2dir-jq

json2dir in jq: `json2dir.jq` reads the raw document text, checks UTF-8, parses JSON with its own strict parser, validates it and emits a shell script, and the POSIX sh launcher `json2dir` runs that script.

    JSON2DIR_JQ=/path/to/jq ./json2dir < tree.json

Limitation: jq replaces invalid UTF-8 with U+FFFD before a program sees it, so a raw (unescaped) U+FFFD in the input is rejected as invalid UTF-8; write it as `\ufffd`.
