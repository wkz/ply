#!/bin/sh
#
# Shellscript that calls ptysnoop.ply
# and filters out ascii keypresses from one process.

# Path to ply
PLY=ply

# File to record ply output into
KEYS=/tmp/keys.txt

# Fail with a message
fail() {
  echo "Error: $1"
  exit 1
}

# Send SIGINT on to ply, but dont kill this shellscript
trap "killall -SIGINT ply" INT

rm -f $KEYS
sudo $PLY ptysnoop.ply > $KEYS || fail "ply didn't exit successfully"

echo ""
echo "Output from bash:"
echo ""

# Note, the awk filter says ash because ply sometimes
# looses the first character.
awk '/ash: / { printf("%s", $2) }' $KEYS | xxd -r -p

# Add more lines like the one above to filter out data from other
# processes, like for instance ssh. See $KEYS for process names.
