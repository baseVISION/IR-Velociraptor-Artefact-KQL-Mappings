// Command baseline-gen generates a KQL function from a baseline rules CSV.
//
// Usage:
//
//	go run . -in baseline_rules_example.csv -scope Supertimeline -out ../../analysis/generated/Windows.Supertimeline.Baseline.kql
//	go run . -in rules.csv                       # defaults: scope=Supertimeline, stdout
//	go run . -in rules.csv -scope PersistenceOverview -fn ApplyPersistenceBaseline
package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// condition represents a single column/operator/value triple.
type condition struct {
	Column string
	Op     string
	Value  string
}

// rule represents one parsed CSV row.
type rule struct {
	Name            string
	Scope           string
	Category        string
	Type            string
	PersistenceType string
	Conditions      []condition
}

// validColumnsByScope maps each scope to its allowed condition target columns.
// PersistenceType is a dedicated scope-guard column (not a condition column).
// Column validation is enforced at parse time; unknown scopes are rejected.
var validColumnsByScope = map[string]map[string]bool{
	"Supertimeline": {
		"Path": true, "Description": true, "Details": true,
		"User": true, "Hash": true, "SourceArtifact": true,
	},
	"PersistenceOverview": {
		"Name": true, "Target": true, "EntryLocation": true,
		"User": true, "Enabled": true, "Signer": true,
		"Hash": true, "Suspicious": true, "SourceArtifact": true,
	},
}

// validOps is the set of supported KQL operators (including negated forms).
var validOps = map[string]bool{
	"has": true, "!has": true,
	"contains": true, "!contains": true,
	"==": true, "!=": true,
	"startswith": true, "!startswith": true,
	"endswith": true, "!endswith": true,
	"matches regex": true,
}

func main() {
	log.SetFlags(0)

	inPath := flag.String("in", "", "path to baseline rules CSV (required)")
	scope := flag.String("scope", "Supertimeline", "scope to filter rules by")
	outPath := flag.String("out", "", "output .kql file (default: stdout)")
	fnName := flag.String("fn", "ApplyTimelineBaseline", "generated KQL function name")
	flag.Parse()

	if *inPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	rules, err := parseCSV(*inPath)
	if err != nil {
		log.Fatalf("parse %s: %v", *inPath, err)
	}

	var w io.Writer = os.Stdout
	if *outPath != "" {
		if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
			log.Fatalf("mkdir: %v", err)
		}
		f, err := os.Create(*outPath)
		if err != nil {
			log.Fatalf("create %s: %v", *outPath, err)
		}
		defer f.Close()
		w = f
	}

	if err := generate(w, rules, *scope, *fnName, filepath.Base(*inPath)); err != nil {
		log.Fatalf("generate: %v", err)
	}
}

// parseCSV reads the CSV and returns all rules.
func parseCSV(path string) ([]rule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1 // allow variable fields
	r.Comment = '#'        // skip # comment lines

	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	idx, err := indexHeader(header)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]int) // rule name → line number
	var rules []rule
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err // csv.ParseError already includes line info
		}
		lineNum, _ := r.FieldPos(0)

		rule, err := parseRow(rec, idx, lineNum)
		if err != nil {
			return nil, err
		}
		if prev, dup := seen[rule.Name]; dup {
			return nil, fmt.Errorf("line %d: duplicate rule name %q (first seen line %d)", lineNum, rule.Name, prev)
		}
		seen[rule.Name] = lineNum
		rules = append(rules, rule)
	}
	return rules, nil
}

// colIndex maps column names to CSV field indices.
type colIndex struct {
	Name               int
	Scope              int
	Category           int
	Type               int
	PersistenceTypeCol int
	Conds              [][3]int // dynamically populated from ColumnN/ModeN/ValueN header triplets
}

func indexHeader(header []string) (colIndex, error) {
	headerIdx := make(map[string]int, len(header))
	for i, h := range header {
		headerIdx[strings.TrimSpace(h)] = i
	}
	get := func(name string) int {
		if i, ok := headerIdx[name]; ok {
			return i
		}
		return -1
	}
	// Dynamically scan for ColumnN/ModeN/ValueN triplets — no fixed limit.
	var conds [][3]int
	for n := 1; ; n++ {
		colKey := fmt.Sprintf("Column%d", n)
		modeKey := fmt.Sprintf("Mode%d", n)
		valKey := fmt.Sprintf("Value%d", n)
		ci, hasCol := headerIdx[colKey]
		mi, hasMode := headerIdx[modeKey]
		vi, hasVal := headerIdx[valKey]
		if !hasCol {
			break
		}
		if !hasMode {
			return colIndex{}, fmt.Errorf("missing %q in header (found %q)", modeKey, colKey)
		}
		if !hasVal {
			return colIndex{}, fmt.Errorf("missing %q in header (found %q)", valKey, colKey)
		}
		conds = append(conds, [3]int{ci, mi, vi})
	}
	if len(conds) == 0 {
		return colIndex{}, fmt.Errorf("missing required CSV column %q in header", "Value1")
	}
	return colIndex{
		Name:               get("RuleName"),
		Scope:              get("Scope"),
		Category:           get("EventCategory"),
		Type:               get("EventType"),
		PersistenceTypeCol: get("PersistenceType"),
		Conds:              conds,
	}, nil
}

func field(rec []string, i int) string {
	if i < 0 || i >= len(rec) {
		return ""
	}
	return strings.TrimSpace(rec[i])
}

func parseRow(rec []string, idx colIndex, lineNum int) (rule, error) {
	name := field(rec, idx.Name)
	if name == "" {
		return rule{}, fmt.Errorf("line %d: empty RuleName", lineNum)
	}

	scope := field(rec, idx.Scope)
	if scope == "" {
		scope = "Supertimeline"
	}
	scopeCols, knownScope := validColumnsByScope[scope]
	if !knownScope {
		return rule{}, fmt.Errorf("line %d (%s): unknown scope %q", lineNum, name, scope)
	}

	var conds []condition
	for _, condCols := range idx.Conds {
		col := field(rec, condCols[0])
		op := field(rec, condCols[1])
		val := field(rec, condCols[2])
		if col == "" {
			continue
		}
		if !scopeCols[col] {
			return rule{}, fmt.Errorf("line %d (%s): invalid column %q for scope %q", lineNum, name, col, scope)
		}
		if !validOps[op] {
			return rule{}, fmt.Errorf("line %d (%s): invalid operator %q", lineNum, name, op)
		}
		if val == "" && op != "==" && op != "!=" {
			return rule{}, fmt.Errorf("line %d (%s): empty value for column %q", lineNum, name, col)
		}
		conds = append(conds, condition{Column: col, Op: op, Value: val})
	}
	if len(conds) == 0 {
		return rule{}, fmt.Errorf("line %d (%s): no conditions defined", lineNum, name)
	}

	category := field(rec, idx.Category)
	typ := field(rec, idx.Type)
	if typ != "" && category == "" {
		return rule{}, fmt.Errorf("line %d (%s): EventType %q set without EventCategory", lineNum, name, typ)
	}

	persistenceType := field(rec, idx.PersistenceTypeCol)
	return rule{
		Name:            name,
		Scope:           scope,
		Category:        category,
		Type:            typ,
		PersistenceType: persistenceType,
		Conditions:      conds,
	}, nil
}

// generate writes the KQL function to w.
func generate(w io.Writer, rules []rule, scope, fnName, srcFile string) error {
	var skipped []string
	var activeRules []rule

	for _, r := range rules {
		if r.Scope != scope {
				skipped = append(skipped, fmt.Sprintf("//        %s - scope=%s", r.Name, r.Scope))
		} else {
			activeRules = append(activeRules, r)
		}
	}

	var writeErr error
	emit := func(format string, args ...any) {
		if writeErr != nil {
			return
		}
		_, writeErr = fmt.Fprintf(w, format+"\n", args...)
	}

	// Header
	emit("// =============================================================================")
	emit("// AUTO-GENERATED by baseline-gen - do not edit manually.")
	emit("// Source: %s", srcFile)
	emit("// Generated: %s", time.Now().UTC().Format(time.RFC3339))
	emit("// Scope: %s | Rules: %d active, %d skipped", scope, len(activeRules), len(skipped))
	emit("// =============================================================================")

	// Function definition
	emit(`.create-or-alter function with (folder="Analysis", docstring="[Generated] Baseline filter for %s. Adds IsBaseline column.", skipvalidation="true")`, scope)
	emit("%s(T:(*)) {", fnName)

	if len(activeRules) == 0 {
		emit("    T")
		emit("    | extend IsBaseline = false")
		emit("}")
		return writeErr
	}

	emit("    T")
	emit("    | extend IsBaseline =")

	for i, r := range activeRules {
		prefix := "        or "
		if i == 0 {
			prefix = "        "
		}

		comment := ruleComment(r)
		emit("        // -- Rule %d: %s --", i+1, comment)

		expr := buildExpression(r)
		emit("%s(%s)", prefix, expr)
	}

	// Skipped rules as comments
	if len(skipped) > 0 {
		emit("        //")
		emit("        // Skipped rules:")
		for _, s := range skipped {
			emit("%s", s)
		}
	}

	emit("}")
	return writeErr
}

// ruleComment builds a human-readable description for the rule comment.
func ruleComment(r rule) string {
	var scopeStr string
	switch {
	case r.Category != "" && r.Type != "":
		scopeStr = r.Category + "/" + r.Type
	case r.Category != "":
		scopeStr = r.Category + "/*"
	case r.PersistenceType != "":
		scopeStr = "PersistenceType=" + r.PersistenceType
	default:
		scopeStr = "unscoped"
	}

	var parts []string
	for _, c := range r.Conditions {
		parts = append(parts, fmt.Sprintf("%s %s", c.Column, c.Op))
	}
	return fmt.Sprintf("%s [%s] (%s)", r.Name, scopeStr, strings.Join(parts, " + "))
}

// buildExpression generates the KQL boolean expression for a rule.
func buildExpression(r rule) string {
	var parts []string

	// Scope guards
	if r.Category != "" {
		parts = append(parts, fmt.Sprintf("EventCategory == %s", kqlString(r.Category)))
		if r.Type != "" {
			parts = append(parts, fmt.Sprintf("EventType == %s", kqlString(r.Type)))
		}
	}
	if r.PersistenceType != "" {
		parts = append(parts, fmt.Sprintf("PersistenceType == %s", kqlString(r.PersistenceType)))
	}

	// Conditions
	for _, c := range r.Conditions {
		col := c.Column
		if col == "Details" {
			col = "tostring(Details)"
		}
		parts = append(parts, conditionExpr(col, c.Op, c.Value))
	}

	return strings.Join(parts, " and ")
}

// conditionExpr builds a single KQL condition expression.
func conditionExpr(col, op, value string) string {
	lit := kqlString(value)

	// != is a native KQL operator — don't decompose it.
	if op == "!=" {
		return fmt.Sprintf("%s != %s", col, lit)
	}

	// Other negated operators: !has → not(... has ...), etc.
	if neg, ok := strings.CutPrefix(op, "!"); ok {
		return fmt.Sprintf("not(%s %s %s)", col, neg, lit)
	}

	return fmt.Sprintf("%s %s %s", col, op, lit)
}

// kqlString returns a KQL string literal. Uses @"..." if the value contains
// backslashes (common in Windows paths), otherwise plain "...".
func kqlString(s string) string {
	if strings.Contains(s, `\`) {
		// KQL verbatim string: @"..." — no escaping needed except for "
		escaped := strings.ReplaceAll(s, `"`, `""`)
		return `@"` + escaped + `"`
	}
	escaped := strings.ReplaceAll(s, `"`, `\"`)
	return `"` + escaped + `"`
}
