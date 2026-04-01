#!/bin/bash

# Script to combine all KQL files from a directory into one file
# Usage: ./combine_mappings.sh [-d|--dir DIRECTORY] [-o|--output FILE] [--list-artifacts] [--exclude-dir DIR]
# Default output file: all_mappings.kql

# Default values
MAPPINGS_DIR="mappings"
ANALYSIS_DIR="analysis"
OUTPUT_FILE="all_mappings.kql"
LIST_ARTIFACTS=false
EXCLUDE_DIRS=()
DIR_EXPLICITLY_SET=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--dir)
            if [[ -z "$2" || "$2" == --* ]]; then
                echo "Error: --dir requires a directory argument" >&2; exit 1
            fi
            MAPPINGS_DIR="$2"
            DIR_EXPLICITLY_SET=true
            shift 2
            ;;
        -o|--output)
            if [[ -z "$2" || "$2" == --* ]]; then
                echo "Error: --output requires a file argument" >&2; exit 1
            fi
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --exclude-dir)
            if [[ -z "$2" || "$2" == --* ]]; then
                echo "Error: --exclude-dir requires a directory argument" >&2; exit 1
            fi
            EXCLUDE_DIRS+=("$2")
            shift 2
            ;;
        --list-artifacts)
            LIST_ARTIFACTS=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [-d|--dir DIRECTORY] [-o|--output FILE] [--list-artifacts] [--exclude-dir DIR]..."
            echo "  -d, --dir           Source directory containing .kql files (default: mappings)"
            echo "  -o, --output FILE   Output file path (default: all_mappings.kql)"
            echo "  --exclude-dir DIR   Exclude a directory from processing (repeatable)"
            echo "                      e.g. --exclude-dir analysis/generated"
            echo "  --list-artifacts    Output artifact list in README markdown format"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use -h or --help for usage information"
            exit 1
            ;;
    esac
done

# Check source directories exist
if [ ! -d "$MAPPINGS_DIR" ]; then
    echo "Error: mappings directory '$MAPPINGS_DIR' not found" >&2
    exit 1
fi
if [ ! -d "$ANALYSIS_DIR" ] && [ "$DIR_EXPLICITLY_SET" = false ]; then
    echo "Error: analysis directory '$ANALYSIS_DIR' not found" >&2
    exit 1
fi

# If --list-artifacts flag is set, output artifact list and exit
if [ "$LIST_ARTIFACTS" = true ]; then
    echo "## Current Parsed Artifacts"
    echo ""
    for file in "$MAPPINGS_DIR"/*.kql; do
        [ ! -e "$file" ] && continue
        
        # Extract artifact name from //ARTIFACT: comment
        artifact=$(grep -m 1 "^//ARTIFACT:" "$file" | sed 's/^\/\/ARTIFACT: //')
        
        if [ -n "$artifact" ]; then
            # Get the base filename without .kql extension
            filename=$(basename "$file" .kql)
            
            # Try to extract a description from comments or use a generic one
            # Look for descriptive comments after the artifact declaration
            echo "- \`$artifact\`"
        fi
    done | sort
    exit 0
fi

# Remove existing output file if it exists
[ -f "$OUTPUT_FILE" ] && rm "$OUTPUT_FILE"

# Create header in output file
cat > "$OUTPUT_FILE" << EOF
// Combined KQL mappings for Velociraptor Artefacts
// Generated on: $(date)
// Source directory: $MAPPINGS_DIR

EOF

file_count=0

_process_file() {
    local file="$1"
    echo "Processing: $file"
    cat >> "$OUTPUT_FILE" << EOF

// ============================================
// Source: $file
// ============================================

EOF
    cat "$file" >> "$OUTPUT_FILE"
    file_count=$((file_count + 1))
}

# Mappings directory (non-recursive, no exclusions needed)
for file in "$MAPPINGS_DIR"/*.kql; do
    [ ! -e "$file" ] && continue
    _process_file "$file"
done

# Analysis directory (recursive so generated/ subdir is included by default)
if [ "$DIR_EXPLICITLY_SET" = false ] && [ -d "$ANALYSIS_DIR" ]; then
while IFS= read -r -d '' file; do
    # Strip leading ./ for consistent prefix matching
    file="${file#./}"

    # Skip files inside excluded directories
    skip=false
    for excl in "${EXCLUDE_DIRS[@]}"; do
        excl="${excl%/}"
        if [[ "$file" == "$excl/"* ]]; then
            skip=true
            break
        fi
    done
    [ "$skip" = true ] && continue

    _process_file "$file"
done < <(find "$ANALYSIS_DIR" -name '*.kql' -type f -print0 | sort -z)
fi

echo -e "\nSuccessfully combined $file_count file(s) into $OUTPUT_FILE"
