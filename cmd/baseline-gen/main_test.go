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
	idx := colIndex{Name: 0, Col1: 1, Mode1: 2, Val1: 3, Enabled: -1,
		Scope: -1, Category: -1, Type: -1,
		Col2: -1, Mode2: -1, Val2: -1, Col3: -1, Mode3: -1, Val3: -1}
	_, err := parseRow([]string{"", "Path", "has", "x"}, idx, 2)
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestParseRow_InvalidColumn(t *testing.T) {
	idx := colIndex{Name: 0, Col1: 1, Mode1: 2, Val1: 3, Enabled: -1,
		Scope: -1, Category: -1, Type: -1,
		Col2: -1, Mode2: -1, Val2: -1, Col3: -1, Mode3: -1, Val3: -1}
	_, err := parseRow([]string{"r1", "BadCol", "has", "x"}, idx, 2)
	if err == nil || !strings.Contains(err.Error(), "invalid column") {
		t.Fatalf("expected 'invalid column' error, got %v", err)
	}
}

func TestParseRow_InvalidOperator(t *testing.T) {
	idx := colIndex{Name: 0, Col1: 1, Mode1: 2, Val1: 3, Enabled: -1,
		Scope: -1, Category: -1, Type: -1,
		Col2: -1, Mode2: -1, Val2: -1, Col3: -1, Mode3: -1, Val3: -1}
	_, err := parseRow([]string{"r1", "Path", "like", "x"}, idx, 2)
	if err == nil || !strings.Contains(err.Error(), "invalid operator") {
		t.Fatalf("expected 'invalid operator' error, got %v", err)
	}
}

func TestParseRow_EmptyValue(t *testing.T) {
	idx := colIndex{Name: 0, Col1: 1, Mode1: 2, Val1: 3, Enabled: -1,
		Scope: -1, Category: -1, Type: -1,
		Col2: -1, Mode2: -1, Val2: -1, Col3: -1, Mode3: -1, Val3: -1}
	_, err := parseRow([]string{"r1", "Path", "has", ""}, idx, 2)
	if err == nil || !strings.Contains(err.Error(), "empty value") {
		t.Fatalf("expected 'empty value' error, got %v", err)
	}
}

func TestParseRow_EventTypeWithoutCategory(t *testing.T) {
	idx := colIndex{Name: 0, Col1: 1, Mode1: 2, Val1: 3,
		Scope: -1, Category: -1, Type: 4, Enabled: -1,
		Col2: -1, Mode2: -1, Val2: -1, Col3: -1, Mode3: -1, Val3: -1}
	_, err := parseRow([]string{"r1", "Path", "has", "x", "ProcessExec"}, idx, 2)
	if err == nil || !strings.Contains(err.Error(), "EventType") {
		t.Fatalf("expected EventType error, got %v", err)
	}
}

func TestParseRow_DefaultScope(t *testing.T) {
	idx := colIndex{Name: 0, Col1: 1, Mode1: 2, Val1: 3,
		Scope: -1, Category: -1, Type: -1, Enabled: -1,
		Col2: -1, Mode2: -1, Val2: -1, Col3: -1, Mode3: -1, Val3: -1}
	r, err := parseRow([]string{"r1", "Path", "has", "x"}, idx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if r.Scope != "Supertimeline" {
		t.Errorf("scope = %q, want Supertimeline", r.Scope)
	}
}

func TestParseRow_DisabledRule(t *testing.T) {
	idx := colIndex{Name: 0, Col1: 1, Mode1: 2, Val1: 3, Enabled: 4,
		Scope: -1, Category: -1, Type: -1,
		Col2: -1, Mode2: -1, Val2: -1, Col3: -1, Mode3: -1, Val3: -1}
	r, err := parseRow([]string{"r1", "Path", "has", "x", "false"}, idx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if r.Enabled {
		t.Error("expected rule to be disabled")
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
		{Name: "disabled", Scope: "Supertimeline", Enabled: false,
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
		{Name: "test_rule", Scope: "Supertimeline", Enabled: true,
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
		{Name: "r1", Scope: "Supertimeline", Enabled: true,
			Conditions: []condition{{Column: "Path", Op: "has", Value: "a"}}},
		{Name: "r2", Scope: "Supertimeline", Enabled: true,
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
		{Name: "active", Scope: "Supertimeline", Enabled: true,
			Conditions: []condition{{Column: "Path", Op: "has", Value: "a"}}},
		{Name: "off", Scope: "Supertimeline", Enabled: false,
			Conditions: []condition{{Column: "Path", Op: "has", Value: "b"}}},
		{Name: "other_scope", Scope: "Other", Enabled: true,
			Conditions: []condition{{Column: "Path", Op: "has", Value: "c"}}},
	}
	err := generate(&buf, rules, "Supertimeline", "TestFn", "test.csv")
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "off — disabled") {
		t.Errorf("missing disabled skip comment:\n%s", out)
	}
	if !strings.Contains(out, "other_scope — scope=Other") {
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
				{Name: "op_test", Scope: "Supertimeline", Enabled: true,
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
	if len(rules) != 11 {
		t.Fatalf("expected 11 rules, got %d", len(rules))
	}

	var buf bytes.Buffer
	err = generate(&buf, rules, "Supertimeline", "ApplyTimelineBaseline", "baseline_rules_example.csv")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	out := buf.String()

	// Should have 9 active rules (1 disabled, 1 wrong scope).
	if strings.Count(out, "// ── Rule") != 9 {
		t.Errorf("expected 9 rule comments, got %d", strings.Count(out, "// ── Rule"))
	}

	// Spot-check specific conditions.
	checks := []string{
		`Path has "svchost.exe"`,                  // svchost
		`User == "SYSTEM"`,                        // svchost condition 2
		`Path contains @"\Windows\Prefetch\"`,     // prefetch with backslash
		`not(Description contains "suspicious")`,  // negated condition
		`disabled_rule_example — disabled`,         // disabled comment
		`persistence_scope_example — scope=PersistenceOverview`, // scope skip
		`EventCategory == "Execution"`,            // scope guard
		`EventType == "ProcessExec"`,              // type guard
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
