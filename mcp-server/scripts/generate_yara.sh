#!/bin/bash

# Output file for all generated .yara rules
OUTPUT_YARA="custom_generated.yara"

# FastAPI scan endpoint
MCP_URL="http://127.0.0.1:8000/scan/"

# File that contains one sample path per line
SAMPLES_LIST="all_samples.txt"

# --- Pre-run Checks ---
if [ ! -f "$SAMPLES_LIST" ]; then
    echo "❌ Error: '$SAMPLES_LIST' not found. Please create it with one sample path per line."
    exit 1
fi

# Clear previous rule output
echo "[+] Clearing previous rules file: $OUTPUT_YARA"
> "$OUTPUT_YARA"

echo "[+] Starting batch scan and YARA rule generation..."

# --- Loop Through Sample Paths ---
while IFS= read -r file || [ -n "$file" ]; do
    # Skip empty or commented lines
    [[ -z "$file" || "$file" =~ ^# ]] && continue

    # Validate sample path
    if [ ! -f "$file" ]; then
        echo "[-] WARNING: Sample not found: $file"
        continue
    fi

    echo "[→] Scanning: $file"

    # Upload sample using curl
    response=$(curl -s -F "file=@$file" "$MCP_URL" -w "%{http_code}")

    http_code="${response: -3}"
    json_body="${response:0:${#response}-3}"

    if [ "$http_code" -eq 200 ]; then
        # Check if the 'rules' key exists and is a non-empty array
        if echo "$json_body" | jq -e '.rules | type == "array" and length > 0' > /dev/null; then
            echo "$json_body" | jq -r '.rules[]' >> "$OUTPUT_YARA"
            echo "[✓] YARA rules generated for $file"
        elif echo "$json_body" | jq -e '.rules | type == "array" and length == 0' > /dev/null; then
            echo "[!] No YARA rules generated for $file"
        else
            echo "[-] ERROR: Unexpected response structure for $file. Expected a 'rules' array."
            echo "$json_body"
        fi
    else
        echo "[-] ERROR: HTTP $http_code from server for $file"
        echo "$json_body"
    fi

done < "$SAMPLES_LIST"

echo ""
echo "[✓] All processing complete. Output saved to '$OUTPUT_YARA'"
echo ""
echo "--- NEXT STEPS ---"
echo "1. Review the generated YARA rules in '$OUTPUT_YARA'."
echo "2. Copy the rules to ClamAV's database directory (requires root):"
echo "   sudo cp \"$OUTPUT_YARA\" /usr/local/share/clamav/"
echo "3. Restart the ClamAV daemon for it to load the new rules:"
echo "   sudo systemctl restart clamav-daemon"
echo "------------------"
