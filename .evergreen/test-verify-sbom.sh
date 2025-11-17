#!/usr/bin/env bash
set -euo pipefail
# test-verify-sbom.sh: Comprehensive test suite for verify-sbom.sh
# Usage: bash .evergreen/test-verify-sbom.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERIFY_SCRIPT="$SCRIPT_DIR/verify-sbom.sh"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

passed=0
failed=0

log() { printf "${BLUE}[test-verify-sbom]${NC} %s\n" "$*"; }
log_pass() { printf "${GREEN}✓${NC} %s\n" "$*"; passed=$((passed + 1)); }
log_fail() { printf "${RED}✗${NC} %s\n" "$*"; failed=$((failed + 1)); }
log_info() { printf "${YELLOW}→${NC} %s\n" "$*"; }

cleanup_files() {
  cd "$REPO_ROOT"
  # Restore any modified files (but don't restore verification scripts)
  git checkout pyproject.toml requirements.txt sbom.json requirements/test.txt requirements/aws.txt 2>/dev/null || true
  # Remove custom test file
  rm -f custom-sbom.json 2>/dev/null || true
  git reset HEAD custom-sbom.json 2>/dev/null || true
}

trap cleanup_files EXIT

cd "$REPO_ROOT"

log "Starting SBOM verification test suite..."
log "Repository: $REPO_ROOT"
log "Verify script: $VERIFY_SCRIPT"
echo ""

# Ensure clean state
cleanup_files

# ============================================================================
# TEST 1: No changes (clean state)
# ============================================================================
log "TEST 1: No changes (clean state)"
if output=$(bash "$VERIFY_SCRIPT" 2>&1); then
  if echo "$output" | grep -q "No manifest changes detected"; then
    log_pass "Test 1: Correctly passed with no changes"
  else
    log_fail "Test 1: Unexpected output - should detect no changes"
    echo "$output"
  fi
else
  log_fail "Test 1: Script failed unexpectedly"
fi
echo ""

# ============================================================================
# TEST 2: Modify pyproject.toml without updating sbom.json
# ============================================================================
log "TEST 2: Modify pyproject.toml without updating sbom.json"
echo "# test comment for verification" >> pyproject.toml
if output=$(bash "$VERIFY_SCRIPT" 2>&1); then
  if echo "$output" | grep -q "FAILURE.*Manifest files changed"; then
    if echo "$output" | grep -q "pyproject.toml"; then
      log_pass "Test 2: Correctly detected pyproject.toml change without SBOM update"
    else
      log_fail "Test 2: Detected failure but didn't identify pyproject.toml"
      echo "$output"
    fi
  else
    log_fail "Test 2: Should have detected manifest change"
    echo "$output"
  fi
else
  # In dry-run mode, script always returns 0
  if echo "$output" | grep -q "FAILURE.*Manifest files changed"; then
    log_pass "Test 2: Correctly detected pyproject.toml change (dry-run mode)"
  else
    log_fail "Test 2: Should have detected manifest change"
    echo "$output"
  fi
fi
git checkout pyproject.toml
echo ""

# ============================================================================
# TEST 3: Modify both pyproject.toml and sbom.json
# ============================================================================
log "TEST 3: Modify both pyproject.toml and sbom.json"
echo "# test comment" >> pyproject.toml
echo "# test update" >> sbom.json
if output=$(bash "$VERIFY_SCRIPT" 2>&1); then
  if echo "$output" | grep -q "SBOM file.*updated alongside manifest changes"; then
    log_pass "Test 3: Correctly passed when both files updated"
  else
    log_fail "Test 3: Should have passed when SBOM updated"
    echo "$output"
  fi
else
  log_fail "Test 3: Script failed unexpectedly"
fi
git checkout pyproject.toml sbom.json
echo ""

# ============================================================================
# TEST 4: Modify requirements.txt without updating sbom.json
# ============================================================================
log "TEST 4: Modify requirements.txt without updating sbom.json"
echo "# test requirement" >> requirements.txt
if output=$(bash "$VERIFY_SCRIPT" 2>&1); then
  if echo "$output" | grep -q "FAILURE.*Manifest files changed"; then
    if echo "$output" | grep -q "requirements.txt"; then
      log_pass "Test 4: Correctly detected requirements.txt change without SBOM update"
    else
      log_fail "Test 4: Detected failure but didn't identify requirements.txt"
      echo "$output"
    fi
  else
    log_fail "Test 4: Should have detected manifest change"
    echo "$output"
  fi
else
  if echo "$output" | grep -q "FAILURE.*Manifest files changed"; then
    log_pass "Test 4: Correctly detected requirements.txt change (dry-run mode)"
  else
    log_fail "Test 4: Should have detected manifest change"
    echo "$output"
  fi
fi
git checkout requirements.txt
echo ""

# ============================================================================
# TEST 5: SKIP_SBOM_VERIFY flag
# ============================================================================
log "TEST 5: SKIP_SBOM_VERIFY flag"
echo "# test" >> pyproject.toml
if output=$(SKIP_SBOM_VERIFY=1 bash "$VERIFY_SCRIPT" 2>&1); then
  if echo "$output" | grep -q "Skipping verification"; then
    log_pass "Test 5: Correctly skipped verification with flag"
  else
    log_fail "Test 5: Should have skipped verification"
    echo "$output"
  fi
else
  log_fail "Test 5: Script failed unexpectedly"
fi
git checkout pyproject.toml
echo ""

# ============================================================================
# TEST 6: Modify nested requirements file
# ============================================================================
log "TEST 6: Modify nested requirements/test.txt"
echo "# test nested" >> requirements/test.txt
if output=$(bash "$VERIFY_SCRIPT" 2>&1); then
  if echo "$output" | grep -q "FAILURE.*Manifest files changed"; then
    if echo "$output" | grep -q "requirements/test.txt"; then
      log_pass "Test 6: Correctly detected nested requirements file change"
    else
      log_fail "Test 6: Detected failure but didn't identify requirements/test.txt"
      echo "$output"
    fi
  else
    log_fail "Test 6: Should have detected nested manifest change"
    echo "$output"
  fi
else
  if echo "$output" | grep -q "FAILURE.*Manifest files changed"; then
    log_pass "Test 6: Correctly detected nested requirements file change (dry-run mode)"
  else
    log_fail "Test 6: Should have detected nested manifest change"
    echo "$output"
  fi
fi
git checkout requirements/test.txt
echo ""

# ============================================================================
# TEST 7: Custom DIFF_BASE parameter
# ============================================================================
log "TEST 7: Custom DIFF_BASE parameter"
if output=$(DIFF_BASE=HEAD~2 bash "$VERIFY_SCRIPT" 2>&1); then
  if echo "$output" | grep -q "Using diff range: HEAD~2..HEAD"; then
    log_pass "Test 7: Correctly used custom DIFF_BASE"
  else
    log_fail "Test 7: Should have used DIFF_BASE=HEAD~2"
    echo "$output"
  fi
else
  log_fail "Test 7: Script failed unexpectedly"
fi
echo ""

# ============================================================================
# TEST 8: VERBOSE mode shows expanded manifests
# ============================================================================
log "TEST 8: VERBOSE mode shows expanded manifests"
if output=$(VERBOSE=1 bash "$VERIFY_SCRIPT" 2>&1); then
  if echo "$output" | grep -q "Expanded manifests:"; then
    if echo "$output" | grep -q "pyproject.toml" && echo "$output" | grep -q "requirements/"; then
      log_pass "Test 8: VERBOSE mode correctly shows expanded manifests"
    else
      log_fail "Test 8: VERBOSE output missing expected manifests"
      echo "$output"
    fi
  else
    log_fail "Test 8: VERBOSE mode should show expanded manifests"
    echo "$output"
  fi
else
  log_fail "Test 8: Script failed unexpectedly"
fi
echo ""

# ============================================================================
# TEST 9: Multiple manifest files changed
# ============================================================================
log "TEST 9: Multiple manifest files changed"
echo "# test1" >> pyproject.toml
echo "# test2" >> requirements.txt
echo "# test3" >> requirements/aws.txt
if output=$(bash "$VERIFY_SCRIPT" 2>&1); then
  if echo "$output" | grep -q "FAILURE.*Manifest files changed"; then
    manifest_count=$(echo "$output" | grep -c "requirements\|pyproject" || echo 0)
    if [[ $manifest_count -ge 3 ]]; then
      log_pass "Test 9: Correctly detected multiple manifest changes"
    else
      log_fail "Test 9: Should have detected all 3 changed manifests"
      echo "$output"
    fi
  else
    log_fail "Test 9: Should have detected manifest changes"
    echo "$output"
  fi
else
  if echo "$output" | grep -q "FAILURE.*Manifest files changed"; then
    log_pass "Test 9: Correctly detected multiple manifest changes (dry-run mode)"
  else
    log_fail "Test 9: Should have detected manifest changes"
    echo "$output"
  fi
fi
git checkout pyproject.toml requirements.txt requirements/aws.txt
echo ""

# ============================================================================
# TEST 10: All requirements/*.txt files are tracked
# ============================================================================
log "TEST 10: All requirements/*.txt files are tracked"
if output=$(VERBOSE=1 bash "$VERIFY_SCRIPT" 2>&1); then
  expanded=$(echo "$output" | sed -n '/Expanded manifests:/,/^$/p')
  missing_files=""
  for req_file in requirements/aws.txt requirements/docs.txt requirements/encryption.txt \
                  requirements/gssapi.txt requirements/ocsp.txt requirements/snappy.txt \
                  requirements/test.txt requirements/zstd.txt; do
    if ! echo "$expanded" | grep -q "$req_file"; then
      missing_files="$missing_files $req_file"
    fi
  done
  
  if [[ -z "$missing_files" ]]; then
    log_pass "Test 10: All requirements/*.txt files are tracked"
  else
    log_fail "Test 10: Missing files from tracking:$missing_files"
    echo "$expanded"
  fi
else
  log_fail "Test 10: Script failed unexpectedly"
fi
echo ""

# ============================================================================
# TEST 11: Custom SBOM_FILE parameter
# ============================================================================
log "TEST 11: Custom SBOM_FILE parameter"
echo "# test" >> pyproject.toml
echo '{}' > custom-sbom.json
git add custom-sbom.json
if output=$(SBOM_FILE=custom-sbom.json bash "$VERIFY_SCRIPT" 2>&1); then
  if echo "$output" | grep -q "SBOM file 'custom-sbom.json' updated"; then
    log_pass "Test 11: Correctly used custom SBOM_FILE"
  else
    log_fail "Test 11: Should have detected custom-sbom.json"
    echo "$output"
  fi
else
  if echo "$output" | grep -q "SBOM file 'custom-sbom.json' updated"; then
    log_pass "Test 11: Correctly used custom SBOM_FILE (dry-run mode)"
  else
    log_fail "Test 11: Should have detected custom-sbom.json"
    echo "$output"
  fi
fi
git checkout pyproject.toml
rm -f custom-sbom.json
git reset HEAD custom-sbom.json 2>/dev/null || true
echo ""

# ============================================================================
# Summary
# ============================================================================
echo "═══════════════════════════════════════════════════════════════════════"
echo "                          TEST RESULTS SUMMARY"
echo "═══════════════════════════════════════════════════════════════════════"
printf "${GREEN}Passed:${NC} %d\n" "$passed"
printf "${RED}Failed:${NC} %d\n" "$failed"
echo "Total:  $((passed + failed))"
echo "═══════════════════════════════════════════════════════════════════════"

if [[ $failed -eq 0 ]]; then
  printf "\n${GREEN}✓ All tests passed!${NC}\n"
  exit 0
else
  printf "\n${RED}✗ Some tests failed!${NC}\n"
  exit 1
fi
