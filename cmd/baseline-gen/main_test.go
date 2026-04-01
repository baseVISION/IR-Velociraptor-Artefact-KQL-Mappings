package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── kqlString ────────────────────────────────────────────────────────────────

func TestKqlString_Plain(t *testing.T) {
	got := kqlString("hello")
	want := `"hello"`
	if got != want {
		t.Errorf("kqlString(%q) = %s, want %s", "hello", got, want)
	}
}

func TestKqlString_Backslash(t *testing.T) {
	got := kqlString(`C:\Windows\System32`)
	want := `@"C:\Windows\System32"`
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestKqlString_QuoteEscaping(t *testing.T) {
	got := kqlString(`say "hi"`)
	want := `"say \"hi\""`
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestKqlString_BackslashAndQuote(t *testing.T) {
	got := kqlString(`C:\"path"`)
	want := `@"C:\""path"""`
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

// ── conditionExpr ────────────────────────────────────────────────────────────

func TestConditionExpr(t *testing.T) {
	tests := []struct {
		col, op, val string
		want         string
	}{
		{"Path", "has", "cmd.exe", `Path has "cmd.exe"`},
		{"Path", "!has", "cmd.exe", `not(Path has "cmd.exe")`},
		{"Path", "contains", `\Windows\`, `Path contains @"\Windows\"`},
		{"Path", "!contains", "suspicious", `not(Path contains "suspicious")`},
		{"User", "==", "SYSTEM", `User == "SYSTEM"`},
		{"User", "!=", "SYSTEM", `User != "SYSTEM"`},
		{"Path", "startswith", `C:\Users\`, `Path startswith @"C:\Users\"`},
		{"Path", "!startswith", `C:\`, `not(Path startswith @"C:\")`},
		{"Path", "endswith", ".exe", `Path endswith ".exe"`},
		{"Path", "!endswith", ".tmp", `not(Path endswith ".tmp")`},
		{"Path", "matches regex", `svc.*exe`, `Path matches regex "svc.*exe"`},
	}
	for _, tt := range tests {
		t.Run(tt.op, func(t *testing.T) {
			got := conditionExpr(tt.col, tt.op, tt.val)
			if got != tt.want {
				t.Errorf("conditionExpr(%q, %q, %q)\n  got  %s\n  want %s", tt.col, tt.op, tt.val, got, tt.want)
			}
		})
	}
}

// ── buildExpression ──────────────────────────────────────────────────────────

func TestBuildExpression_Unscoped(t *testing.T) {
	r := rule{
		Name:       "test",
		Conditions: []condition{{Column: "Path", Op: "has", Value: "cmd.exe"}},
	}
	got := buildExpression(r)
	want := `Path has "cmd.exe"`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildExpression_CategoryOnly(t *testing.T) {
	r := rule{
		Name:     "test",
		Category: "Execution",
		Conditions: []condition{
			{Column: "Path", Op: "has", Value: "wmi.exe"},
		},
	}
	got := buildExpression(r)
	want := `EventCategory == "Execution" and Path has "wmi.exe"`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildExpression_CategoryAndType(t *testing.T) {
	r := rule{
		Name:     "test",
		Category: "Execution",
		Type:     "ProcessExec",
		Conditions: []condition{
			{Column: "Path", Op: "has", Value: "svc.exe"},
			{Column: "User", Op: "==", Value: "SYSTEM"},
		},
	}
	got := buildExpression(r)
	want := `EventCategory == "Execution" and EventType == "ProcessExec" and Path has "svc.exe" and User == "SYSTEM"`
	if got != want {
		t.Errorf("got\n  %s\nwant\n  %s", got, want)
	}
}

func TestBuildExpression_DetailsColumn(t *testing.T) {
	r := rule{
		Name:       "test",
		Conditions: []condition{{Column: "Details", Op: "has", Value: "foo"}},
	}
	got := buildExpression(r)
	want := `tostring(Details) has "foo"`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// ── parseRow ─────────────────────────────────────────────────────────────────

func TestParseRow_EmptyName(t *testing.T) {
	idx := colIndex{Name: 0, Scope: -1, Category: -1, Type: -1, PersistenceTypeCol: -1,
		Conds: [][3]int{{1, 2, 3}}}
	_, err := parseRow([]string{"", "Path", "has", "x"}, idx, 2)
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestParseRow_InvalidColumn(t *testing.T) {
	idx := colIndex{Name: 0, Scope: -1, Category: -1, Type: -1, PersistenceTypeCol: -1,
		Conds: [][3]int{{1, 2, 3}}}
	_, err := parseRow([]string{"r1", "BadCol", "has", "x"}, idx, 2)
	if err == nil || !strings.Contains(err.Error(), "invalid column") {
		t.Fatalf("expected 'invalid column' error, got %v", err)
	}
}

func TestParseRow_InvalidOperator(t *testing.T) {
	idx := colIndex{Name: 0, Scope: -1, Category: -1, Type: -1, PersistenceTypeCol: -1,
		Conds: [][3]int{{1, 2, 3}}}
	_, err := parseRow([]string{"r1", "Path", "like", "x"}, idx, 2)
	if err == nil || !strings.Contains(err.Error(), "invalid operator") {
		t.Fatalf("expected 'invalid operator' error, got %v", err)
	}
}

func TestParseRow_EmptyValue(t *testing.T) {
	idx := colIndex{Name: 0, Scope: -1, Category: -1, Type: -1, PersistenceTypeCol: -1,
		Conds: [][3]int{{1, 2, 3}}}
	_, err := parseRow([]string{"r1", "Path", "has", ""}, idx, 2)
	if err == nil || !strings.Contains(err.Error(), "empty value") {
		t.Fatalf("expected 'empty value' error, got %v", err)
	}
}

func TestParseRow_EventTypeWithoutCategory(t *testing.T) {
	idx := colIndex{Name: 0, Scope: -1, Category: -1, Type: 4, PersistenceTypeCol: -1,
		Conds: [][3]int{{1, 2, 3}}}
	_, err := parseRow([]string{"r1", "Path", "has", "x", "ProcessExec"}, idx, 2)
	if err == nil || !strings.Contains(err.Error(), "EventType") {
		t.Fatalf("expected EventType error, got %v", err)
	}
}

func TestParseRow_DefaultScope(t *testing.T) {
	idx := colIndex{Name: 0, Scope: -1, Category: -1, Type: -1, PersistenceTypeCol: -1,
		Conds: [][3]int{{1, 2, 3}}}
	r, err := parseRow([]string{"r1", "Path", "has", "x"}, idx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if r.Scope != "Supertimeline" {
		t.Errorf("scope = %q, want Supertimeline", r.Scope)
	}
}

// ── indexHeader ───────────────────────────────────────────────────────────────

func TestIndexHeader_MissingRequired(t *testing.T) {
	_, err := indexHeader([]string{"RuleName", "Column1", "Mode1"})
	if err == nil || !strings.Contains(err.Error(), "Value1") {
		t.Fatalf("expected missing Value1 error, got %v", err)
	}
}

// ── generate ─────────────────────────────────────────────────────────────────

func TestGenerate_NoActiveRules(t *testing.T) {
	var buf bytes.Buffer
	rules := []rule{
		{Name: "other", Scope: "Other",
			Conditions: []condition{{Column: "Path", Op: "has", Value: "x"}}},
	}
	err := generate(&buf, rules, "Supertimeline", "TestFn", "test.csv")
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "IsBaseline = false") {
		t.Error("expected fallback IsBaseline = false for zero active rules")
	}
}

func TestGenerate_SingleRule(t *testing.T) {
	var buf bytes.Buffer
	rules := []rule{
		{Name: "test_rule", Scope: "Supertimeline",
			Conditions: []condition{{Column: "Path", Op: "has", Value: "cmd.exe"}}},
	}
	err := generate(&buf, rules, "Supertimeline", "TestFn", "test.csv")
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, `Path has "cmd.exe"`) {
		t.Errorf("missing condition in output:\n%s", out)
	}
	if !strings.Contains(out, "Rule 1: test_rule") {
		t.Errorf("missing rule comment in output:\n%s", out)
	}
	if !strings.Contains(out, "AUTO-GENERATED") {
		t.Error("missing header")
	}
}

func TestGenerate_MultipleRulesUseOr(t *testing.T) {
	var buf bytes.Buffer
	rules := []rule{
		{Name: "r1", Scope: "Supertimeline",
			Conditions: []condition{{Column: "Path", Op: "has", Value: "a"}}},
		{Name: "r2", Scope: "Supertimeline",
			Conditions: []condition{{Column: "Path", Op: "has", Value: "b"}}},
	}
	err := generate(&buf, rules, "Supertimeline", "TestFn", "test.csv")
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "or (") {
		t.Errorf("expected 'or (' for second rule:\n%s", out)
	}
}

func TestGenerate_SkippedRuleComment(t *testing.T) {
	var buf bytes.Buffer
	rules := []rule{
		{Name: "active", Scope: "Supertimeline",
			Conditions: []condition{{Column: "Path", Op: "has", Value: "a"}}},
		{Name: "other_scope", Scope: "Other",
			Conditions: []condition{{Column: "Path", Op: "has", Value: "c"}}},
	}
	err := generate(&buf, rules, "Supertimeline", "TestFn", "test.csv")
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "other_scope - scope=Other") {
		t.Errorf("missing scope skip comment:\n%s", out)
	}
}

// ── per-operator generate ────────────────────────────────────────────────────

func TestGenerate_AllOperators(t *testing.T) {
	tests := []struct {
		op   string
		val  string
		want string
	}{
		{"has", "cmd.exe", `Path has "cmd.exe"`},
		{"!has", "cmd.exe", `not(Path has "cmd.exe")`},
		{"contains", `\Windows\`, `Path contains @"\Windows\"`},
		{"!contains", "temp", `not(Path contains "temp")`},
		{"==", "SYSTEM", `Path == "SYSTEM"`},
		{"!=", "SYSTEM", `Path != "SYSTEM"`},
		{"startswith", `C:\Users\`, `Path startswith @"C:\Users\"`},
		{"!startswith", `C:\`, `not(Path startswith @"C:\")`},
		{"endswith", ".exe", `Path endswith ".exe"`},
		{"!endswith", ".tmp", `not(Path endswith ".tmp")`},
		{"matches regex", `svc.*exe`, `Path matches regex "svc.*exe"`},
	}
	for _, tt := range tests {
		t.Run(tt.op, func(t *testing.T) {
			var buf bytes.Buffer
			rules := []rule{
				{Name: "op_test", Scope: "Supertimeline",
					Conditions: []condition{{Column: "Path", Op: tt.op, Value: tt.val}}},
			}
			err := generate(&buf, rules, "Supertimeline", "TestFn", "test.csv")
			if err != nil {
				t.Fatal(err)
			}
			out := buf.String()
			if !strings.Contains(out, tt.want) {
				t.Errorf("operator %q: expected %q in output:\n%s", tt.op, tt.want, out)
			}
		})
	}
}

// ── end-to-end ───────────────────────────────────────────────────────────────

func TestEndToEnd_ExampleCSV(t *testing.T) {
	// Locate the example CSV relative to the test file.
	csvPath := "baseline_rules_example.csv"
	if _, err := os.Stat(csvPath); err != nil {
		t.Skipf("example CSV not found at %s: %v", csvPath, err)
	}

	rules, err := parseCSV(csvPath)
	if err != nil {
		t.Fatalf("parseCSV: %v", err)
	}
	if len(rules) != 10 {
		t.Fatalf("expected 10 rules, got %d", len(rules))
	}

	var buf bytes.Buffer
	err = generate(&buf, rules, "Supertimeline", "ApplyTimelineBaseline", "baseline_rules_example.csv")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	out := buf.String()

	// Should have 9 active rules (1 wrong scope).
	if strings.Count(out, "// -- Rule") != 9 {
		t.Errorf("expected 9 rule comments, got %d", strings.Count(out, "// -- Rule"))
	}

	// Spot-check specific conditions.
	checks := []string{
		`Path has "svchost.exe"`,                                // svchost
		`User == "SYSTEM"`,                                      // svchost condition 2
		`Path contains @"\Windows\Prefetch\"`,                   // prefetch with backslash
		`not(Description contains "suspicious")`,                // negated condition
		`persistence_scope_example - scope=PersistenceOverview`, // scope skip
		`EventCategory == "Execution"`,                          // scope guard
		`EventType == "ProcessExec"`,                            // type guard
	}
	for _, c := range checks {
		if !strings.Contains(out, c) {
			t.Errorf("missing expected content: %s", c)
		}
	}
}

func TestEndToEnd_DuplicateName(t *testing.T) {
	csv := "RuleName,Column1,Mode1,Value1\nr1,Path,has,a\nr1,Path,has,b\n"
	tmp := t.TempDir()
	p := filepath.Join(tmp, "dup.csv")
	if err := os.WriteFile(p, []byte(csv), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := parseCSV(p)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate error, got %v", err)
	}
}

func TestEndToEnd_NoConditions(t *testing.T) {
	csv := "RuleName,Column1,Mode1,Value1\nr1,,,\n"
	tmp := t.TempDir()
	p := filepath.Join(tmp, "empty.csv")
	if err := os.WriteFile(p, []byte(csv), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := parseCSV(p)
	if err == nil || !strings.Contains(err.Error(), "no conditions") {
		t.Fatalf("expected 'no conditions' error, got %v", err)
	}
}

// ── scope-keyed column validation ────────────────────────────────────────────

func TestParseRow_PersistenceColumnsValid(t *testing.T) {
	// PersistenceType as dedicated scope guard, Name as condition column.
	idx := colIndex{Name: 0, Scope: 1, Category: -1, Type: -1, PersistenceTypeCol: 2,
		Conds: [][3]int{{3, 4, 5}}}
	r, err := parseRow([]string{"r1", "PersistenceOverview", "Boot Execute", "Name", "==", "autocheck autochk *"}, idx, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Scope != "PersistenceOverview" {
		t.Errorf("scope = %q, want PersistenceOverview", r.Scope)
	}
	if r.PersistenceType != "Boot Execute" {
		t.Errorf("PersistenceType = %q, want Boot Execute", r.PersistenceType)
	}
}

func TestParseRow_CrossScopeColumnRejected(t *testing.T) {
	// Path is a Supertimeline column; should be rejected for PersistenceOverview.
	idx := colIndex{Name: 0, Scope: 1, Category: -1, Type: -1, PersistenceTypeCol: -1,
		Conds: [][3]int{{2, 3, 4}}}
	_, err := parseRow([]string{"r1", "PersistenceOverview", "Path", "has", "x"}, idx, 2)
	if err == nil || !strings.Contains(err.Error(), "invalid column") {
		t.Fatalf("expected 'invalid column' error, got %v", err)
	}
	if !strings.Contains(err.Error(), "PersistenceOverview") {
		t.Errorf("error should mention scope, got: %v", err)
	}
}

func TestParseRow_UnknownScopeRejected(t *testing.T) {
	idx := colIndex{Name: 0, Scope: 1, Category: -1, Type: -1, PersistenceTypeCol: -1,
		Conds: [][3]int{{2, 3, 4}}}
	_, err := parseRow([]string{"r1", "UnknownScope", "Path", "has", "x"}, idx, 2)
	if err == nil || !strings.Contains(err.Error(), "unknown scope") {
		t.Fatalf("expected 'unknown scope' error, got %v", err)
	}
}

func TestParseRow_EmptyValueEqualityAllowed(t *testing.T) {
	// Suspicious == "" is a valid rule (empty string comparison).
	idx := colIndex{Name: 0, Scope: 1, Category: -1, Type: -1, PersistenceTypeCol: -1,
		Conds: [][3]int{{2, 3, 4}}}
	r, err := parseRow([]string{"r1", "PersistenceOverview", "Suspicious", "==", ""}, idx, 2)
	if err != nil {
		t.Fatalf("unexpected error for empty == value: %v", err)
	}
	if r.Conditions[0].Value != "" {
		t.Errorf("value = %q, want empty string", r.Conditions[0].Value)
	}
}

func TestGenerate_EmptyValueEquality(t *testing.T) {
	var buf bytes.Buffer
	rules := []rule{
		{Name: "no_flags", Scope: "PersistenceOverview",
			Conditions: []condition{{Column: "Suspicious", Op: "==", Value: ""}}},
	}
	err := generate(&buf, rules, "PersistenceOverview", "TestFn", "test.csv")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `Suspicious == ""`) {
		t.Errorf("expected Suspicious == \"\" in output:\n%s", buf.String())
	}
}

// ── PersistenceType scope guard ─────────────────────────────────────────────────

func TestBuildExpression_PersistenceTypeGuard(t *testing.T) {
	r := rule{
		Name:            "test",
		Scope:           "PersistenceOverview",
		PersistenceType: "Boot Execute",
		Conditions: []condition{
			{Column: "Name", Op: "==", Value: "autocheck autochk *"},
		},
	}
	got := buildExpression(r)
	want := `PersistenceType == "Boot Execute" and Name == "autocheck autochk *"`
	if got != want {
		t.Errorf("got\n  %s\nwant\n  %s", got, want)
	}
}

func TestIndexHeader_DynamicFourConditions(t *testing.T) {
	header := []string{
		"RuleName", "Scope", "EventCategory", "EventType", "PersistenceType",
		"Column1", "Mode1", "Value1",
		"Column2", "Mode2", "Value2",
		"Column3", "Mode3", "Value3",
		"Column4", "Mode4", "Value4",
	}
	idx, err := indexHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.Conds) != 4 {
		t.Errorf("expected 4 condition triplets, got %d", len(idx.Conds))
	}
	if idx.PersistenceTypeCol < 0 {
		t.Error("PersistenceTypeCol should be set")
	}
}

func TestIndexHeader_MissingModeRejected(t *testing.T) {
	// Column2 present but Mode2 missing.
	header := []string{"RuleName", "Column1", "Mode1", "Value1", "Column2", "Value2"}
	_, err := indexHeader(header)
	if err == nil || !strings.Contains(err.Error(), "Mode2") {
		t.Fatalf("expected missing Mode2 error, got %v", err)
	}
}

func TestEndToEnd_PersistenceCSV(t *testing.T) {
	// Build a minimal in-memory persistence CSV with 4 conditions.
	csv := "RuleName,Scope,EventCategory,EventType,PersistenceType,Column1,Mode1,Value1,Column2,Mode2,Value2,Column3,Mode3,Value3,Column4,Mode4,Value4\n" +
		"boot_exec,PersistenceOverview,,,Boot Execute,Name,==,autocheck autochk *,Target,contains,\\autochk.exe,Signer,startswith,(Verified) Microsoft,Suspicious,==,\n"
	tmp := t.TempDir()
	p := filepath.Join(tmp, "persistence.csv")
	if err := os.WriteFile(p, []byte(csv), 0o644); err != nil {
		t.Fatal(err)
	}
	rules, err := parseCSV(p)
	if err != nil {
		t.Fatalf("parseCSV: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].PersistenceType != "Boot Execute" {
		t.Errorf("PersistenceType = %q, want Boot Execute", rules[0].PersistenceType)
	}
	if len(rules[0].Conditions) != 4 {
		t.Errorf("expected 4 conditions, got %d", len(rules[0].Conditions))
	}
	var buf bytes.Buffer
	if err := generate(&buf, rules, "PersistenceOverview", "ApplyPersistenceBaseline", "persistence.csv"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	checks := []string{
		`PersistenceType == "Boot Execute"`,
		`Name == "autocheck autochk *"`,
		`Target contains @"\autochk.exe"`,
		`Signer startswith "(Verified) Microsoft"`,
		`Suspicious == ""`,
	}
	for _, c := range checks {
		if !strings.Contains(out, c) {
			t.Errorf("missing %q in output:\n%s", c, out)
		}
	}
}
