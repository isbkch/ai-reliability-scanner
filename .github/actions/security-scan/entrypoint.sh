#!/bin/bash

set -e

# Function to log messages
log() {
    echo "::notice::$1"
}

error() {
    echo "::error::$1"
}

# Parse inputs
SCAN_PATH="${1:-./}"
OUTPUT_FORMAT="${INPUT_OUTPUT_FORMAT:-sarif}"
OUTPUT_FILE="${INPUT_OUTPUT_FILE:-reliability-results.sarif}"
SEVERITY_THRESHOLD="${INPUT_SEVERITY_THRESHOLD:-MEDIUM}"
LANGUAGES="${INPUT_LANGUAGES:-python,javascript}"
ENABLE_AI="${INPUT_ENABLE_AI_ANALYSIS:-true}"
FAIL_ON_FINDINGS="${INPUT_FAIL_ON_FINDINGS:-true}"
UPLOAD_SARIF="${INPUT_UPLOAD_SARIF:-true}"

log "Starting AI Reliability Scanner"
log "Scan path: $SCAN_PATH"
log "Output format: $OUTPUT_FORMAT"
log "Output file: $OUTPUT_FILE"
log "Severity threshold: $SEVERITY_THRESHOLD"
log "Languages: $LANGUAGES"
log "AI analysis enabled: $ENABLE_AI"

# Build scan command
SCAN_CMD="ai-reliability-scanner scan $SCAN_PATH"
SCAN_CMD="$SCAN_CMD --output $OUTPUT_FORMAT"
SCAN_CMD="$SCAN_CMD --file $OUTPUT_FILE"
SCAN_CMD="$SCAN_CMD --severity $SEVERITY_THRESHOLD"

# Add language filters
IFS=',' read -ra LANG_ARRAY <<< "$LANGUAGES"
for lang in "${LANG_ARRAY[@]}"; do
    SCAN_CMD="$SCAN_CMD --language $lang"
done

# Add AI flag if disabled
if [ "$ENABLE_AI" = "false" ]; then
    SCAN_CMD="$SCAN_CMD --no-ai"
fi

log "Running: $SCAN_CMD"

# Run the scan
if eval "$SCAN_CMD"; then
    SCAN_EXIT_CODE=0
else
    SCAN_EXIT_CODE=$?
fi

# Check if output file exists
if [ ! -f "$OUTPUT_FILE" ]; then
    error "Output file not found: $OUTPUT_FILE"
    exit 1
fi

# Parse results if SARIF format
if [ "$OUTPUT_FORMAT" = "sarif" ]; then
    # Extract metrics from SARIF file
    FINDINGS_FOUND=$(jq '.runs[0].results | length' "$OUTPUT_FILE" 2>/dev/null || echo "0")
    
    # Get scan duration and files scanned from SARIF properties
    SCAN_DURATION=$(jq -r '.runs[0].invocations[0].executionSuccessful // "unknown"' "$OUTPUT_FILE" 2>/dev/null || echo "unknown")
    FILES_SCANNED=$(jq -r '.runs[0].artifacts | length' "$OUTPUT_FILE" 2>/dev/null || echo "0")
else
    # For other formats, set default values
    FINDINGS_FOUND="unknown"
    SCAN_DURATION="unknown"
    FILES_SCANNED="unknown"
fi

# Set outputs
echo "findings-found=$FINDINGS_FOUND" >> $GITHUB_OUTPUT
echo "vulnerabilities-found=$FINDINGS_FOUND" >> $GITHUB_OUTPUT
echo "scan-duration=$SCAN_DURATION" >> $GITHUB_OUTPUT
echo "files-scanned=$FILES_SCANNED" >> $GITHUB_OUTPUT
echo "results-file=$OUTPUT_FILE" >> $GITHUB_OUTPUT

log "Findings found: $FINDINGS_FOUND"
log "Files scanned: $FILES_SCANNED"
log "Results saved to: $OUTPUT_FILE"

# Upload SARIF file to GitHub code scanning.
if [ "$OUTPUT_FORMAT" = "sarif" ] && [ "$UPLOAD_SARIF" = "true" ] && [ "$FINDINGS_FOUND" != "0" ]; then
    log "Uploading SARIF results to GitHub code scanning"
    
    # Use GitHub CLI to upload SARIF
    if command -v gh &> /dev/null; then
        gh api \
            --method POST \
            -H "Accept: application/vnd.github+json" \
            /repos/$GITHUB_REPOSITORY/code-scanning/sarifs \
            --input "$OUTPUT_FILE" || true
    else
        log "GitHub CLI not available, skipping SARIF upload"
    fi
fi

# Create job summary
{
    echo "# AI Reliability Scanner Results"
    echo ""
    echo "| Metric | Value |"
    echo "|--------|-------|"
    echo "| Findings Found | $FINDINGS_FOUND |"
    echo "| Files Scanned | $FILES_SCANNED |"
    echo "| Scan Duration | $SCAN_DURATION |"
    echo "| Output Format | $OUTPUT_FORMAT |"
    echo ""
    
    if [ "$FINDINGS_FOUND" != "0" ] && [ "$FINDINGS_FOUND" != "unknown" ]; then
        echo "**Reliability findings detected.** Please review the results."
        echo ""
        echo "[View detailed results]($GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID)"
    else
        echo "**No reliability findings found.**"
    fi
} >> $GITHUB_STEP_SUMMARY

# Determine exit code
if [ "$FAIL_ON_FINDINGS" = "true" ] && [ "$FINDINGS_FOUND" != "0" ] && [ "$FINDINGS_FOUND" != "unknown" ]; then
    error "Reliability findings found and fail-on-findings is enabled"
    exit 1
elif [ $SCAN_EXIT_CODE -ne 0 ]; then
    error "Scanner failed with exit code $SCAN_EXIT_CODE"
    exit $SCAN_EXIT_CODE
else
    log "Scan completed successfully"
    exit 0
fi
