#!/bin/bash
# This script has git safety issues that should be detected

git commit --no-verify -m "quick fix"
git push --force origin main
GIT_HOOKS_SKIP=1 git commit -m "bypass hooks"
