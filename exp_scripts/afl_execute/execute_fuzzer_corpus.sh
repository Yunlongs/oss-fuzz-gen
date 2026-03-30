#!/bin/bash
# Execute fuzzer on corpus and export profdata

set -e

# Check if the correct number of arguments is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <corpus_dir> <fuzzer>"
    echo "  fuzzer: Path to the fuzzer executable"
    exit 1
fi

CORPUS_DIR="/corpus"
FUZZER="$1"
SAVE_DIR=/cov

# Validate inputs
if [ ! -d "$CORPUS_DIR" ]; then
    echo "Error: Corpus directory '$CORPUS_DIR' does not exist"
    exit 1
fi

if [ -z "$(ls -A "$CORPUS_DIR")" ]; then
    echo "Error: Corpus directory '$CORPUS_DIR' is empty"
    exit 1
fi


if [ ! -f "$FUZZER" ]; then
    echo "Error: Fuzzer '$FUZZER' does not exist"
    exit 1
fi

if [ ! -x "$FUZZER" ]; then
    echo "Error: Fuzzer '$FUZZER' is not executable"
    exit 1
fi

# Create save directory if it doesn't exist
mkdir -p "$SAVE_DIR"

FUZZER_NAME=$(basename "$FUZZER")
export LLVM_PROFILE_FILE="$SAVE_DIR/$FUZZER_NAME.profraw"

echo "Executing fuzzer on corpus..."
echo "Corpus directory: $CORPUS_DIR"
echo "Fuzzer: $FUZZER"
echo "Profdata will be saved to: $SAVE_DIR/$FUZZER_NAME.profdata"

# Execute fuzzer on each corpus file
# Use the fuzzer in a way that processes all corpus files
cd /out

$FUZZER $CORPUS_DIR -runs=0

echo "Merging profraw files to profdata..."
# Merge all profraw files into a single profdata file
llvm-profdata merge -sparse "$SAVE_DIR"/$FUZZER_NAME.profraw -o "$SAVE_DIR/$FUZZER_NAME.profdata"

# Clean up temporary profraw files
rm -rf "$SAVE_DIR/$FUZZER_NAME.profraw"

echo "Successfully saved profdata to: $SAVE_DIR/$FUZZER_NAME.profdata"
