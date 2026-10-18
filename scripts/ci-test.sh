#!/usr/bin/env bash
# Keep the complete console log and expose its useful tail in public annotations.
set -euo pipefail
log=$(mktemp)
trap 'rm -f "$log"' EXIT
if cargo test "$@" 2>&1 | tee "$log"; then
  exit 0
else
  status=${PIPESTATUS[0]}
  if [[ ${GITHUB_ACTIONS:-} == true ]]; then
    python3 - "$log" <<'PY'
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(errors="replace")
text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
# GitHub truncates long annotation messages at the beginning. Keep the failure,
# rather than several kilobytes of successful compilation and test output.
text = text[-2800:]
text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
print("::error title=Cargo test failure::" + text)
PY
  fi
  exit "$status"
fi
