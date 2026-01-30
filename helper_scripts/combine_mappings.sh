#!/bin/bash

# Script to combine all KQL files from a directory into one file
# Usage: ./combine_mappings.sh [-d|--dir DIRECTORY] [--list-artifacts]
# Output file: all_mappings.kql

# Default values
MAPPINGS_DIR="mappings"
OUTPUT_FILE="all_mappings.kql"
LIST_ARTIFACTS=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--dir)
            MAPPINGS_DIR="$2"
            shift 2
            ;;
        --list-artifacts)
            LIST_ARTIFACTS=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [-d|--dir DIRECTORY] [--list-artifacts]"
            echo "  -d, --dir           Source directory containing .kql files (default: mappings)"
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

# Check if mappings directory exists
if [ ! -d "$MAPPINGS_DIR" ]; then
    echo "Error: $MAPPINGS_DIR directory not found"
    exit 1
fi

# If --list-artifacts flag is set, output artifact list and exit
if [ "$LIST_ARTIFACTS" = true ]; then
    echo "## Current Parsed Artifacts"
    echo ""
    for file in "$MAPPINGS_DIR"/*.kql; do
        [ ! -e "$file" ] && echo "No .kql files found in $MAPPINGS_DIR" && exit 1
        
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

# Loop through all .kql files in mappings directory
for file in "$MAPPINGS_DIR"/*.kql; do
    # Check if glob matched any files
    [ ! -e "$file" ] && echo "No .kql files found in $MAPPINGS_DIR" && exit 1
    
    echo "Processing: $file"
    
    # Add separator and filename with single heredoc
    cat >> "$OUTPUT_FILE" << EOF

// ============================================
// Source: $file
// ============================================

EOF
    
    # Append file content
    cat "$file" >> "$OUTPUT_FILE"
    
    file_count=$((file_count + 1))
done

echo -e "\nSuccessfully combined $file_count file(s) into $OUTPUT_FILE"
