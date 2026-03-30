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
	Name       string
	Scope      string
	Category   string
	Type       string
	Conditions []condition
	Enabled    bool
}

// validColumns is the set of columns that can be targeted by conditions.
var validColumns = map[string]bool{
	"Path": true, "Description": true, "Details": true,
	"User": true, "Hash": true, "SourceArtifact": true,
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
	lineNum := 1
	for {
		lineNum++
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNum, err)
		}

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
	Name, Scope, Category, Type int
	Col1, Mode1, Val1           int
	Col2, Mode2, Val2           int
	Col3, Mode3, Val3           int
	Enabled                     int
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
	// Validate required columns exist.
	for _, required := range []string{"RuleName", "Column1", "Mode1", "Value1"} {
		if _, ok := headerIdx[required]; !ok {
			return colIndex{}, fmt.Errorf("missing required CSV column %q in header", required)
		}
	}
	return colIndex{
		Name: get("RuleName"), Scope: get("Scope"),
		Category: get("EventCategory"), Type: get("EventType"),
		Col1: get("Column1"), Mode1: get("Mode1"), Val1: get("Value1"),
		Col2: get("Column2"), Mode2: get("Mode2"), Val2: get("Value2"),
		Col3: get("Column3"), Mode3: get("Mode3"), Val3: get("Value3"),
		Enabled: get("IsEnabled"),
	}, nil
}

func field(rec []string, i int) string {
	if i < 0 || i >= len(rec) {
		return ""
	}
	return strings.TrimSpace(rec[i])
}

func fieldRaw(rec []string, i int) string {
	if i < 0 || i >= len(rec) {
		return ""
	}
	return rec[i]
}

func parseRow(rec []string, idx colIndex, lineNum int) (rule, error) {
	name := field(rec, idx.Name)
	if name == "" {
		return rule{}, fmt.Errorf("line %d: empty RuleName", lineNum)
	}

	enabled := true
	if v := field(rec, idx.Enabled); v != "" {
		enabled = strings.EqualFold(v, "true")
	}

	var conds []condition
	for _, condCols := range [][3]int{
		{idx.Col1, idx.Mode1, idx.Val1},
		{idx.Col2, idx.Mode2, idx.Val2},
		{idx.Col3, idx.Mode3, idx.Val3},
	} {
		col := field(rec, condCols[0])
		op := field(rec, condCols[1])
		val := fieldRaw(rec, condCols[2])
		if col == "" {
			continue
		}
		if !validColumns[col] {
			return rule{}, fmt.Errorf("line %d (%s): invalid column %q", lineNum, name, col)
		}
		if !validOps[op] {
			return rule{}, fmt.Errorf("line %d (%s): invalid operator %q", lineNum, name, op)
		}
		if val == "" {
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

	scope := field(rec, idx.Scope)
	if scope == "" {
		scope = "Supertimeline"
	}

	return rule{
		Name:       name,
		Scope:      scope,
		Category:   category,
		Type:       typ,
		Conditions: conds,
		Enabled:    enabled,
	}, nil
}

// generate writes the KQL function to w.
func generate(w io.Writer, rules []rule, scope, fnName, srcFile string) error {
	var skipped []string
	var activeRules []rule

	for _, r := range rules {
		switch {
		case !r.Enabled:
			skipped = append(skipped, fmt.Sprintf("//        %s — disabled", r.Name))
		case r.Scope != scope:
			skipped = append(skipped, fmt.Sprintf("//        %s — scope=%s", r.Name, r.Scope))
		default:
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
	emit("// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	emit("// AUTO-GENERATED by baseline-codegen — do not edit manually.")
	emit("// Source: %s", srcFile)
	emit("// Generated: %s", time.Now().UTC().Format(time.RFC3339))
	emit("// Scope: %s | Rules: %d active, %d skipped", scope, len(activeRules), len(skipped))
	emit("// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

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
		emit("        // ── Rule %d: %s ──", i+1, comment)

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
