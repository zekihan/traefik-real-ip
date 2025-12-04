#!/bin/bash

set -e

DIR=$( cd -P -- "$(dirname -- "$(command -v -- "$0")")" && pwd -P )

cd "${DIR}/.."

# Fetch a URL with retries, exponential backoff, and validation.
# Usage: fetch_with_retries.sh <url> <output-file> [max-attempts] [force-http1]

URL="${1:?URL required}"
OUTPUT="${2:?Output file required}"
MAX_ATTEMPTS="${3:-8}"
FORCE_HTTP1="${4:-true}"

TMP_FILE="${OUTPUT}.tmp"

attempt=1

while (( attempt <= MAX_ATTEMPTS )); do
    echo "[$(date +"%Y-%m-%d %H:%M:%S")] Attempt $attempt/$MAX_ATTEMPTS fetching: $URL"

    if [[ "$FORCE_HTTP1" == "true" ]]; then
        CURL_HTTP_FLAG="--http1.1"
    else
        CURL_HTTP_FLAG=""
    fi

    if curl $CURL_HTTP_FLAG -fsSL --max-time 20 "$URL" -o "$TMP_FILE"; then
        if [[ -s "$TMP_FILE" ]]; then
            mv "$TMP_FILE" "$OUTPUT"
            echo "Success: saved to $OUTPUT"
            exit 0
        else
            echo "Warning: empty response received."
        fi
    else
        echo "Warning: curl failed."
    fi

    # Exponential backoff: 2,4,8,16,…
    sleep $(( 2 ** (attempt - 1) ))
    ((attempt++))
done

echo "ERROR: Failed to fetch $URL after $MAX_ATTEMPTS attempts."

# If no previous file exists, we must fail hard.
if [[ ! -f "$OUTPUT" ]]; then
    echo "No previous file to fall back to: $OUTPUT does not exist."
    exit 1
fi

echo "Fallback: keeping existing file $OUTPUT"
exit 0