#!/bin/sh
#
# Refreshes the cipher-suite data used by the mapper module.
#
# It downloads ciphersuites.json from ciphersuite.info and regenerates
# src/main/java/com/ibm/mapper/mapper/ssl/json/JsonCipherSuites.java from it.
#
# This is NOT part of the Maven build. Run it by hand when you want to pick up
# new cipher suites, or let the update-cipher-suites workflow run it for you.
# Both files are checked into git, so the change shows up as a reviewable diff.
#
# After running this, format the generated Java file:
#     mvn -pl mapper spotless:apply
# The generator writes one entry per line and no license header. Spotless adds
# the header and the normal formatting.

set -eu

url=https://ciphersuite.info/api/cs/
target=ciphersuites.json
tmp=$(mktemp)
# Do not leave the temp file behind if we exit early.
trap 'rm -f "$tmp"' EXIT

# --fail makes curl exit non-zero on a 4xx/5xx instead of writing the error
# page to disk. We download to a temp file so a bad response can never
# overwrite the good data we already have.
if ! curl --fail --silent --show-error --location --max-time 60 "$url" -o "$tmp"; then
    echo "Failed to download $url - keeping the current $target" >&2
    exit 1
fi

# The API has to give us parseable JSON with a plausible number of entries.
# A sharp drop means the API changed or returned a partial body, and we would
# rather stop than commit a shrunken cipher-suite list.
new_count=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["ciphersuites"]))' "$tmp")
old_count=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["ciphersuites"]))' "$target")

if [ "$new_count" -lt $(( old_count * 9 / 10 )) ]; then
    echo "Refusing to update: $url returned $new_count entries, down from $old_count." >&2
    echo "If this drop is real, update $target by hand." >&2
    exit 1
fi

mv "$tmp" "$target"
echo "Updated $target: $old_count -> $new_count cipher suites"

python3 creatCipherSuiteClass.py
echo "Regenerated JsonCipherSuites.java - now run: mvn -pl mapper spotless:apply"
