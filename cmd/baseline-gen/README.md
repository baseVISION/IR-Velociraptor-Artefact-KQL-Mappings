# baseline-gen

Reads a baseline rules CSV and generates a native KQL function (`ApplyTimelineBaseline`) that compiles all rules inline for efficient filtering. 

## Usage

```sh
# Generate and write to file
go run . -in baseline_rules_example.csv -out ../../analysis/generated/Windows.Supertimeline.Baseline.kql

# Different scope and function name
go run . -in rules.csv -scope PersistenceOverview -fn ApplyPersistenceBaseline -out ../../analysis/generated/Windows.Persistence.Baseline.kql

# Print to stdout
go run . -in baseline_rules_example.csv
```

| Flag    | Default                  | Description                        |
|---------|--------------------------|------------------------------------|
| `-in`   | *(required)*             | Path to baseline rules CSV         |
| `-scope`| `Supertimeline`          | Only emit rules matching this scope|
| `-fn`   | `ApplyTimelineBaseline`  | Generated KQL function name        |
| `-out`  | stdout                   | Output `.kql` file path            |

## CSV schema

```
RuleName,Scope,EventCategory,EventType,Column1,Mode1,Value1,Column2,Mode2,Value2,Column3,Mode3,Value3,IsEnabled
```

| Column           | Required | Notes |
|------------------|----------|-------|
| `RuleName`       | yes      | Unique identifier, no spaces |
| `Scope`          | no       | Defaults to `Supertimeline` if empty |
| `EventCategory`  | no       | Leave empty to match all categories |
| `EventType`      | no       | Requires `EventCategory` if set |
| `Column1–3`      | Col1 required | `Path`, `Description`, `Details`, `User`, `Hash`, `SourceArtifact` |
| `Mode1–3`        | Col1 required | See operators below |
| `Value1–3`       | Col1 required | Match value; empty Col means that slot is skipped |
| `IsEnabled`      | no       | `true`/`false`; defaults to `true` if empty |

### Supported operators

| Operator        | KQL output                    |
|-----------------|-------------------------------|
| `has`           | `col has "val"`               |
| `!has`          | `not(col has "val")`          |
| `contains`      | `col contains "val"`          |
| `!contains`     | `not(col contains "val")`     |
| `==`            | `col == "val"`                |
| `!=`            | `col != "val"`                |
| `startswith`    | `col startswith "val"`        |
| `!startswith`   | `not(col startswith "val")`   |
| `endswith`      | `col endswith "val"`          |
| `!endswith`     | `not(col endswith "val")`     |
| `matches regex` | `col matches regex "val"`     |

Values containing backslashes are emitted as KQL verbatim strings (`@"..."`).  
Multiple conditions (Col1–3) are combined with `and`.

## Development workflow

1. Find noise in a materialised timeline:
   ```kql
   stored_query_result("Timeline_Host1")
   | summarize Count=count() by EventCategory, EventType, Path
   | order by Count desc | take 50
   ```

2. Preview a candidate rule before committing (uses `TestBaselineRule()` in ADX):
   ```kql
   TestBaselineRule("Timeline_Host1", "Path", "has", "svchost.exe", "Execution", "SRUMExecution")
   ```

3. Add the rule to `baseline_rules_example.csv` with `IsEnabled=true`.

4. Regenerate and deploy:
   ```sh
   go run . -in baseline_rules_example.csv -out ../../analysis/generated/Windows.Supertimeline.Baseline.kql
   ```

5. Run tests:
   ```sh
   go test ./...
   ```
