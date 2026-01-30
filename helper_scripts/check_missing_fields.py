#!/usr/bin/env python3
"""
Compare fields in sample data against KQL mapping files to find missing fields

Usage:
    python check_missing_fields.py [--samples SAMPLE_FILE] [--mappings MAPPINGS_DIR]
    
Examples:
    python check_missing_fields.py
    python check_missing_fields.py --samples data/samples.txt --mappings kql_mappings/
"""
import json
import re
import argparse
from pathlib import Path
from collections import defaultdict

# Compile regex patterns once for performance
SAMPLE_PATTERN = re.compile(r"'([^']+)',.*dynamic\(({.*})\)")
TABLE_PATTERN = re.compile(r'\.create table \w+\s*\([^)]+', re.DOTALL)
COLUMN_PATTERN = re.compile(r'(\w+):\s*(?:string|datetime|long|int|bool|dynamic)')

# KQL field extraction patterns
TYPE_CONVERSION_PATTERNS = [
    re.compile(rf'(\w+)\s*=\s*{func}\(RawData\.(\w+)\)')
    for func in ['tobool', 'tostring', 'todatetime', 'tolong', 'toint']
]

BRACKET_PATTERNS = [
    re.compile(rf'(\w+)\s*=\s*{func}\(RawData\.?\[[\"\'](.+?)[\"\']\]\)')
    for func in ['tobool', 'tostring', 'todatetime', 'tolong', 'toint']
]

DYNAMIC_PATTERN = re.compile(r'(\w+)\s*=\s*RawData\.(\w+)(?!\.)(?:\s|,|$)')
DYNAMIC_BRACKET_PATTERN = re.compile(r'(\w+)\s*=\s*RawData\.\[[\"\'](.+?)[\"\']\](?:\s|,|$)')
NESTED_BRACKET_PATTERN = re.compile(r'RawData\.\[[\"\'](.+?)[\"\']\]\.(\w+)')
NESTED_DOT_PATTERN = re.compile(r'RawData\.(\w+)\.(\w+)')
FUNCTION_NAME_PATTERN = re.compile(r'function\s+Route{}\s*\(\).*?(?=\.create|\.alter|$)', re.DOTALL)

def get_artifact_filter_from_kql(kql_path):
    """Extract the complete artifact filter logic from a KQL file"""
    try:
        with open(kql_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Look for the where clause with Artifact filter
        # Pattern: where Artifact == "..." or where Artifact startswith "..." and ...
        where_match = re.search(r'where\s+Artifact\s+[^|]*', content, re.IGNORECASE)
        if not where_match:
            return None
        
        where_clause = where_match.group(0)
        return where_clause
    except:
        return None

def artifact_matches_filter(artifact, where_clause):
    """Evaluate if an artifact matches a KQL where clause"""
    if not where_clause:
        return False
    
    # Parse conditions: Artifact == "X", Artifact startswith "Y", Artifact != "Z"
    # Handle AND logic
    
    # Check for exact match
    exact_match = re.search(r'Artifact\s+==\s+["\']([^"\']+)["\']', where_clause)
    if exact_match:
        return artifact == exact_match.group(1)
    
    # Check for startswith with optional exclusions
    startswith_match = re.search(r'Artifact\s+startswith\s+["\']([^"\']+)["\']', where_clause)
    if startswith_match:
        prefix = startswith_match.group(1)
        if not artifact.startswith(prefix):
            return False
        
        # Check for exclusions (AND Artifact != "...")
        exclusions = re.findall(r'Artifact\s+!=\s+["\']([^"\']+)["\']', where_clause)
        for exclusion in exclusions:
            if artifact == exclusion:
                return False
        
        return True
    
    # Check for contains
    contains_match = re.search(r'Artifact\s+contains\s+["\']([^"\']+)["\']', where_clause)
    if contains_match:
        return contains_match.group(1) in artifact
    
    return False

def extract_fields_from_sample(sample_line):
    """Extract artifact name and all fields from a sample data line"""
    # Parse the datatable line which is in format: 'ArtifactName', ..., dynamic({...})
    match = SAMPLE_PATTERN.search(sample_line)
    if not match:
        return None, set(), set()
    
    artifact = match.group(1)
    json_str = match.group(2)
    
    try:
        data = json.loads(json_str)
        # Get all top-level keys from the JSON
        fields = set(data.keys())
        
        # Also check for nested fields that might be important
        nested_fields = set()
        for key, value in data.items():
            if isinstance(value, dict):
                # Add nested keys with dot notation
                for nested_key in value.keys():
                    nested_fields.add(f"{key}.{nested_key}")
        
        return artifact, fields, nested_fields
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON for {artifact}: {e}")
        return artifact, set(), set()

def extract_fields_from_kql(kql_path, artifact_name=None):
    """Extract fields being mapped in a KQL file, optionally for a specific artifact"""
    try:
        with open(kql_path, 'r', encoding='utf-8') as f:
            full_content = f.read()
        
        content = full_content
        # If artifact_name is specified, try to find the function for that specific artifact
        if artifact_name:
            # Create function name from artifact (e.g., "Windows.Forensics.SAM/Parsed" -> "RouteWindowsForensicsSAMParsed")
            func_name = artifact_name.replace(".", "").replace("/", "").replace(" ", "")
            pattern = re.compile(rf'function\s+Route{func_name}\s*\(\).*?(?=\.create|\.alter|$)', re.DOTALL)
            func_match = pattern.search(content)
            if func_match:
                content = func_match.group(0)
        
        fields = set()
        dynamic_parents = set()
        
        # Extract table column names from table definition to recognize standard columns
        table_columns = set()
        table_match = TABLE_PATTERN.search(full_content)
        if table_match:
            table_def = table_match.group(0)
            for col_match in COLUMN_PATTERN.finditer(table_def):
                table_columns.add(col_match.group(1))
        
        # Find all field mappings in extend statements using compiled patterns
        for pattern in TYPE_CONVERSION_PATTERNS:
            for match in pattern.finditer(content):
                fields.add(match.group(2))
        
        # Handle bracket notation for fields with special characters
        for pattern in BRACKET_PATTERNS:
            for match in pattern.finditer(content):
                source_field = match.group(2)
                # Unescape the field name (remove backslashes before quotes)
                source_field = source_field.replace(r'\"', '"')
                fields.add(source_field)
        
        # Find dynamic field mappings (these capture entire nested objects)
        for match in DYNAMIC_PATTERN.finditer(content):
            source_field = match.group(2)
            fields.add(source_field)
            dynamic_parents.add(source_field)
        
        # Handle dynamic bracket notation
        for match in DYNAMIC_BRACKET_PATTERN.finditer(content):
            source_field = match.group(2)
            # Unescape the field name
            source_field = source_field.replace(r'\"', '"')
            fields.add(source_field)
            dynamic_parents.add(source_field)
        
        # Handle nested field access like RawData.["Computer Info"].Name
        for match in NESTED_BRACKET_PATTERN.finditer(content):
            parent = match.group(1).replace(r'\"', '"')
            child = match.group(2)
            fields.add(f"{parent}.{child}")
            fields.add(parent)
        
        # Handle nested access with dot notation like RawData.Hash.MD5
        for match in NESTED_DOT_PATTERN.finditer(content):
            parent = match.group(1)
            child = match.group(2)
            fields.add(f"{parent}.{child}")
            fields.add(parent)
        
        return fields, dynamic_parents, table_columns
    except Exception as e:
        print(f"Error reading {kql_path}: {e}")
        return set(), set(), set()

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='Compare fields in sample data against KQL mapping files to find missing fields',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s
  %(prog)s --samples data/samples.txt
  %(prog)s --samples samples.txt --mappings custom_mappings/
        """
    )
    parser.add_argument(
        '--samples',
        type=str,
        default='samples.txt',
        help='Path to the sample data file (default: samples.txt)'
    )
    parser.add_argument(
        '--mappings',
        type=str,
        default='mappings',
        help='Path to the mappings directory (default: mappings)'
    )
    
    args = parser.parse_args()
    
    # Read samples
    samples_path = Path(args.samples)
    mappings_dir = Path(args.mappings)
    
    if not samples_path.exists():
        print(f"❌ Error: Sample file not found: {samples_path}")
        print(f"   Please provide a valid sample file path using --samples")
        return 1
    
    if not mappings_dir.exists():
        print(f"❌ Error: Mappings directory not found: {mappings_dir}")
        print(f"   Please provide a valid mappings directory using --mappings")
        return 1
    
    artifacts_data = defaultdict(lambda: {"fields": set(), "nested": set()})
    
    print(f"Reading sample data from: {samples_path}")
    print(f"Using mappings from: {mappings_dir}")
    print("\n⚠️  NOTE: This analysis may not be 100% accurate. Known limitations:")
    print("   - Field names with special characters (%, parentheses, quotes) may be flagged as missing")
    print("   - Complex function call field names may not be detected")
    print("   - Manual verification recommended for flagged fields\n")
    with open(samples_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('datatable') or line == ']':
                continue
            
            artifact, fields, nested = extract_fields_from_sample(line)
            if artifact:
                artifacts_data[artifact]["fields"].update(fields)
                artifacts_data[artifact]["nested"].update(nested)
    
    print(f"\nFound {len(artifacts_data)} unique artifacts in samples\n")
    
    # Check each artifact against its KQL mapping
    missing_report = []
    
    for artifact, data in sorted(artifacts_data.items()):
        # Try multiple file naming strategies
        kql_path = None
        
        # Strategy 1: Exact match with dots (e.g., Windows.Forensics.SAM.Parsed.kql)
        kql_filename = artifact.replace("/", ".") + ".kql"
        if (mappings_dir / kql_filename).exists():
            kql_path = mappings_dir / kql_filename
        
        # Strategy 2: Base artifact name (e.g., Windows.Forensics.SAM.kql for Windows.Forensics.SAM/Parsed)
        if not kql_path and "/" in artifact:
            base_artifact = artifact.split("/")[0]
            base_filename = base_artifact + ".kql"
            if (mappings_dir / base_filename).exists():
                kql_path = mappings_dir / base_filename
                kql_filename = base_filename + f" (contains {artifact})"
        
        # Strategy 3: Scan all KQL files for pattern matches (startswith, contains, etc.)
        # Prefer the most specific match (e.g., longest prefix for startswith)
        if not kql_path:
            best_match = None
            best_specificity = 0
            
            for kql_file in mappings_dir.glob("*.kql"):
                where_clause = get_artifact_filter_from_kql(kql_file)
                if where_clause and artifact_matches_filter(artifact, where_clause):
                    # Calculate specificity score
                    specificity = 0
                    
                    # Exact match is most specific
                    if f'== "{artifact}"' in where_clause:
                        specificity = 1000
                    # startswith - specificity is length of prefix
                    else:
                        startswith_match = re.search(r'startswith\s+["\']([^"\']+)["\']', where_clause)
                        if startswith_match:
                            specificity = len(startswith_match.group(1))
                    
                    # Keep the most specific match
                    if specificity > best_specificity:
                        best_specificity = specificity
                        best_match = kql_file
                        # Extract the pattern for display
                        if "startswith" in where_clause:
                            pattern_type = "startswith pattern"
                        elif "contains" in where_clause:
                            pattern_type = "contains pattern"
                        else:
                            pattern_type = "filter match"
                        best_filename = kql_file.name + f" (matches via {pattern_type})"
            
            if best_match:
                kql_path = best_match
                kql_filename = best_filename
        
        if not kql_path:
            missing_report.append(f"\n❌ NO MAPPING FILE: {artifact}")
            missing_report.append(f"   Expected file: {artifact.replace('/', '.')}.kql or {artifact.split('/')[0]}.kql")
            missing_report.append(f"   Sample fields: {sorted(data['fields'])[:10]}")  # Show first 10
            continue
        
        # Extract fields from KQL
        # Special case: Linux.Collection.Uploads uses generic table with specific functions per artifact
        # For this file, we need to extract fields from the specific artifact's function
        if kql_path.name == "Linux.Collection.Uploads.kql":
            kql_fields, dynamic_parents, table_columns = extract_fields_from_kql(kql_path, artifact)
        else:
            # For all other files, extract fields normally (pass artifact name to find specific function if needed)
            kql_fields, dynamic_parents, table_columns = extract_fields_from_kql(kql_path, artifact)
        
        # Find missing fields - use intelligent matching
        # Combine both top-level and nested fields from sample
        sample_fields = data["fields"] | data["nested"]
        
        # Remove redundant 'timestamp' field - it's always the same as outer Timestamp
        sample_fields.discard("timestamp")
        
        # Remove nested fields under known dynamic parents (e.g., EventData.*, System.*)
        # When parent is stored as dynamic, all children are automatically captured
        sample_fields = {f for f in sample_fields if not any(f.startswith(dp + ".") for dp in ['EventData', 'System'])}
        
        covered_fields = set()
        
        # Pre-compute lookup tables for performance
        kql_fields_lower = {f.lower(): f for f in kql_fields}
        table_columns_lower = {c.lower(): c for c in table_columns}
        flattened_kql = {f.replace(".", "").lower(): f for f in kql_fields}
        
        for field in sample_fields:
            # Exact match
            if field in kql_fields:
                covered_fields.add(field)
                continue
                
            # Case-insensitive match
            if field.lower() in kql_fields_lower:
                covered_fields.add(field)
                continue
            
            # Table column match (e.g., "hostname" in sample but "Hostname" in table)
            if field.lower() in table_columns_lower:
                covered_fields.add(field)
                continue
            
            # Space variation (e.g., "Network Info" vs "NetworkInfo")
            if field.replace(" ", "").lower() in kql_fields_lower:
                covered_fields.add(field)
                continue
            
            # Flattened match (e.g., "Laddr.IP" -> "LaddrIP")
            if field.replace(".", "").lower() in flattened_kql:
                covered_fields.add(field)
                continue
            
            # Nested field covered by dynamic parent
            if "." in field:
                # Use rsplit to get parent from the LAST dot (handles complex field names)
                parent = field.rsplit(".", 1)[0]
                if parent in dynamic_parents:
                    covered_fields.add(field)
                    continue
                # Check case-insensitive parent
                parent_lower = parent.lower()
                if parent_lower in kql_fields_lower and kql_fields_lower[parent_lower] in dynamic_parents:
                    covered_fields.add(field)
                    continue
        
        missing_fields = sample_fields - covered_fields
        
        # Check for obsolete fields (in KQL but not in sample data)
        # These might indicate removed/renamed fields in Velociraptor
        standard_columns = {'Timestamp', 'Hostname', 'Artifact', 'Organization', 
                           'ClientId', 'FlowId', 'IngestionTime'}
        # Known optional/redundant fields that shouldn't trigger warnings
        # timestamp: redundant with outer Timestamp column
        # Upload.*: these fields vary by upload success/failure and file type
        expected_optional = {
            'timestamp', 
            'Upload.Error',           # Only present on failed uploads
            'Upload.StoredSize',      # Optional, not always present
            'Upload.sha256',          # Optional hash field
            'Upload.md5',             # Optional hash field
            'Upload.Accessor',        # Optional upload metadata
            'Upload.Components',      # Optional upload metadata
            'Upload.StoredName'       # Optional storage name
        }
        
        obsolete_fields = (kql_fields - sample_fields - standard_columns - table_columns - expected_optional)
        
        # Filter out nested field parents that might not appear in sample
        obsolete_fields = {f for f in obsolete_fields if '.' not in f or f not in dynamic_parents}
        
        if missing_fields:
            missing_report.append(f"\n⚠️  {artifact} ({kql_filename})")
            missing_report.append(f"   Missing {len(missing_fields)} field(s):")
            for field in sorted(missing_fields):
                missing_report.append(f"      - {field}")
        
        if obsolete_fields:
            missing_report.append(f"\n⚠️  {artifact} ({kql_filename})")
            missing_report.append(f"   Obsolete {len(obsolete_fields)} field(s) (in KQL but not in sample):")
            for field in sorted(obsolete_fields):
                missing_report.append(f"      - {field}")
        
        if not missing_fields and not obsolete_fields:
            print(f"✓ {artifact} - All fields mapped")
    
    # Print summary
    total_artifacts = len(artifacts_data)
    artifacts_with_issues = len([line for line in missing_report if line.strip().startswith('⚠️')])
    complete_artifacts = total_artifacts - artifacts_with_issues
    
    if missing_report:
        print("\n" + "="*80)
        print("FIELD MISMATCH REPORT")
        print("="*80)
        for line in missing_report:
            print(line)
        print("\n" + "="*80)
        print(f"SUMMARY: {complete_artifacts}/{total_artifacts} artifacts complete")
        print(f"         {artifacts_with_issues} artifact(s) with field mismatches")
        print("\n⚠️  Note: Obsolete fields may indicate removed/renamed fields in Velociraptor")
        print("         or optional fields not present in this sample data.")
        print("="*80)
    else:
        print("\n✓ All artifacts have complete field mappings!")
    
    return 0

if __name__ == "__main__":
    exit(main())