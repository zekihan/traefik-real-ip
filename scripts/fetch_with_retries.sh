#!/bin/bash

set -e

DIR=$( cd -P -- "$(dirname -- "$(command -v -- "$0")")" && pwd -P )

cd "${DIR}/.."

# Fetch a nonempty response with retries and exponential backoff.
# Usage: fetch_with_retries.sh <url> <output-file> [max-attempts] [force-http1]

URL="${1:?URL required}"
OUTPUT="${2:?Output file required}"
MAX_ATTEMPTS="${3:-8}"
FORCE_HTTP1="${4:-true}"

TMP_FILE="${OUTPUT}.tmp"
trap 'rm -f -- "$TMP_FILE"' EXIT

CURL_HTTP_FLAGS=()
if [[ "$FORCE_HTTP1" == "true" ]]; then
    CURL_HTTP_FLAGS=(--http1.1)
fi

attempt=1

while (( attempt <= MAX_ATTEMPTS )); do
    echo "[$(date +"%Y-%m-%d %H:%M:%S")] Attempt $attempt/$MAX_ATTEMPTS fetching: $URL"

    if curl "${CURL_HTTP_FLAGS[@]}" -fsSL --max-time 20 "$URL" -o "$TMP_FILE"; then
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
    if (( attempt < MAX_ATTEMPTS )); then
        sleep $(( 2 ** (attempt - 1) ))
    fi
    ((attempt++))
done

echo "ERROR: Failed to fetch $URL after $MAX_ATTEMPTS attempts." >&2
exit 1
