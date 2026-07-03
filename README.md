# Velociraptor Artefact KQL Mappings

KQL mappings for parsing Velociraptor forensic artifacts into Azure Data Explorer tables. Automatically routes per artifacts from raw ingestion to structured tables.

> **Disclaimer:** This project is a work in progress and covers a subset of available Velociraptor artifacts. Mappings are provided as-is and may contain errors. Always validate against your data before production use.


## Structure

- **`Ingress_Setup_RawVelociraptorEvents.kql`** - Creates the raw ingestion table (one-time setup)
- **`all_mappings.kql`** - Generated deployment artifact (execute against cluster)
- **`mappings/`** - Individual KQL files per artifact (table + routing function + update policy)
- **`helper_scripts/combine_mappings.sh`** - Merges all mappings into deployment file
- **`.github/.copilot-instructions.md`** - Development guidelines for creating new mappings

## Current Parsed Artifacts
- `DetectRaptor.Windows.Detection.Amcache`
- `DetectRaptor.Windows.Detection.Applications`
- `DetectRaptor.Windows.Detection.BinaryRename`
- `DetectRaptor.Windows.Detection.Evtx`
- `DetectRaptor.Windows.Detection.HijackLibsMFT`
- `DetectRaptor.Windows.Detection.LolRMM`
- `DetectRaptor.Windows.Detection.MFT`
- `DetectRaptor.Windows.Detection.Powershell.PSReadline`
- `DetectRaptor.Windows.Detection.Webhistory`
- `DetectRaptor.Windows.Detection.YaraProcessWin`
- `Generic.Applications.Chrome.SessionStorage`
- `Generic.Applications.Office.Keywords`
- `Generic.Client.DiskSpace`
- `Generic.Client.DiskUsage`
- `Generic.Client.Info/WindowsInfo`
- `Generic.Client.VQL`
- `Generic.Detection.HashHunter`
- `Generic.Network.InterfaceAddresses`
- `Generic.System.EfiSignatures/Certificates`
- `Generic.System.ProcessSiblings`
- `IRIS.Sync.Asset`
- `Linux.Applications.Docker.Info`
- `Linux.Applications.Docker.Version`
- `Linux.Collection.*`
- `Linux.Collection.CatScale`
- `Linux.Detection.AnomalousFiles`
- `Linux.Detection.BruteForce/btmp.logs, Linux.Detection.BruteForce/wtmp.logs`
- `Linux.Detection.IncorrectPermissions/Discrepancies`
- `Linux.ExtractKthread/extractKthread`
- `Linux.Forensics.EnvironmentVariables/LoginScriptsDetection, Linux.Forensics.EnvironmentVariables/ModifierDetection`
- `Linux.Forensics.Journal`
- `Linux.Forensics.ProcFD/DeletedFiles, Linux.Forensics.ProcFD/DeviceFiles, Linux.Forensics.ProcFD/RegularFiles, Linux.Forensics.ProcFD/Sockets`
- `Linux.Forensics.RecentlyUsed/Recent Entries`
- `Linux.Forensics.Targets/*`
- `Linux.Memory.AVML`
- `Linux.Mounts`
- `Linux.Network.NetstatEnriched`
- `Linux.Network.Netstat/TCP4, Linux.Network.Netstat/TCP6`
- `Linux.Network.Netstat.Watcher/RemoteConnectionsDiffMonitor`
- `Linux.Network.NM.Connections/ConnectionConfigs`
- `Linux.Proc.Arp`
- `Linux.Proc.Modules`
- `Linux.Sys.ACPITables`
- `Linux.Sys.BashHistory`
- `Linux.Sys.CPUTime`
- `Linux.Sys.Crontab/CronScripts`
- `Linux.Sys.Getcap`
- `Linux.Sys.Groups`
- `Linux.Sys.JournalCtl`
- `Linux.Sys.LastUserLogin`
- `Linux.Sys.LogHunter`
- `Linux.Sys.Maps`
- `Linux.Sys.Modinfo`
- `Linux.Sys.Pslist`
- `Linux.Sys.Services`
- `Linux.Sys.SUID`
- `Linux.Sys.SystemdTimer`
- `Linux.System.BashLogout`
- `Linux.System.PAM`
- `Linux.Sys.Users`
- `Linux.Users.InteractiveUsers`
- `Linux.Users.RootUsers`
- `Network.ExternalIpAddress`
- `Server.Hunts.CancelAndDelete/HuntFiles`
- `Server.Import.ArtifactExchange`
- `Server.Import.Extras`
- `Server.Orgs.NewOrg`
- `Server.Utils.CreateLinuxPackages`
- `Server.Utils.CreateMSI`
- `Server.Utils.DeleteEvents`
- `System.VFS.DownloadFile`
- `System.VFS.ListDirectory/Listing`
- `Windows.Analysis.EvidenceOfDownload`
- `Windows.Attack.ParentProcess`
- `Windows.Attack.Prefetch`
- `Windows.Collectors.File/All Matches Metadata`
- `Windows.Detection.Amcache`
- `Windows.Detection.BinaryHunter`
- `Windows.Detection.BinaryRename`
- `Windows.Detection.Malfind`
- `Windows.Detection.Mutants/Handles`
- `Windows.EventLogs.Evtx`
- `Windows.EventLogs.Hayabusa/Results`
- `Windows.EventLogs.LogonSessions`
- `Windows.Forensics.Amcache/InventoryApplicationFile`
- `Windows.Forensics.Amcache/InventoryDevicePnp`
- `Windows.Forensics.Amcache/InventoryDriverBinary`
- `Windows.Forensics.CertUtil`
- `Windows.Forensics.Clipboard`
- `Windows.Forensics.FilenameSearch`
- `Windows.Forensics.Lnk`
- `Windows.Forensics.PartitionTable`
- `Windows.Forensics.Prefetch`
- `Windows.Forensics.RecycleBin`
- `Windows.Forensics.SAM/CreateTimes`
- `Windows.Forensics.Shellbags`
- `Windows.Forensics.SRUM/Execution Stats`
- `Windows.Forensics.Timeline`
- `Windows.Forensics.UEFI`
- `Windows.Forensics.Usn`
- `Windows.Hayabusa.Rules`
- `Windows.Network.ArpCache`
- `Windows.Network.InterfaceAddresses`
- `Windows.Network.ListeningPorts`
- `Windows.Network.Netstat`
- `Windows.Network.NetstatEnriched/Netstat`
- `Windows.NTFS.ADSHunter`
- `Windows.NTFS.MFT`
- `Windows.Packs.LateralMovement/AlternateLogon`
- `Windows.Packs.Persistence/Startup Items`
- `Windows.Persistence.PermanentWMIEvents`
- `Windows.Registry.NTUser`
- `Windows.Registry.ScheduledTasks`
- `Windows.Registry.Sysinternals.Eulacheck/RegistryAPI`
- `Windows.Registry.UserAssist`
- `Windows.Sys.FirewallRules`
- `Windows.Sys.Interfaces`
- `Windows.Sysinternals.Autoruns`
- `Windows.Sys.StartupItems`
- `Windows.Sys.Users`
- `Windows.System.AppCompatPCA`
- `Windows.System.LocalAdmins`
- `Windows.System.Powershell.ModuleAnalysisCache`
- `Windows.System.Powershell.PSReadline`
- `Windows.System.Pslist`
- `Windows.System.Services`
- `Windows.System.Shares`
- `Windows.System.TaskScheduler/Analysis`
- `Windows.System.WMIProviders`
- `Windows.System.WMIQuery`
- `Windows.Timeline.MFT`
- `Windows.Timeline.Prefetch.Improved`
- `Windows.Triage.Targets/SearchGlobs`

## Quick Start

1. **One-time setup:** Execute `Ingress_Setup_RawVelociraptorEvents.kql` against your Azure Data Explorer cluster
2. **Deploy mappings:** Execute `all_mappings.kql` against your cluster
3. **Ingest data:** Send Velociraptor output to `RawVelociraptorEvents` table
4. **Query:** Data automatically routes to artifact-specific tables (e.g., `WindowsForensicsPrefetch`, `LinuxSysPslist`)

## Performance Tuning

### Ingestion Latency

See [`ADX_Ingestion_Performance.md`](ADX_Ingestion_Performance.md) for streaming ingestion and batching policy commands.

### Query Result Limits

ADX default limits (500k rows / 64 MB) will truncate large supertimeline queries. Apply once per cluster:

```kql
.alter-merge workload_group default '{"RequestLimitsPolicy":{"MaxResultBytes":{"IsRelaxable":true,"Value":2073741824},"MaxResultRecords":{"IsRelaxable":true,"Value":2000000}}}'
```

This sets a 2 million row cap and a 2 GB byte cap. `IsRelaxable: true` means individual queries can still override downward.

## Development Workflow

**Creating/updating mappings:**

1. Generate sample data: Run `helper_scripts/generate_sample_data.kql` in ADX, save output as `samples.txt`
2. Create mapping in `mappings/` directory (see `.github/.copilot-instructions.md` for patterns)
3. Validate: `python3 helper_scripts/check_missing_fields.py`
4. Build: `./helper_scripts/combine_mappings.sh`
5. Deploy: Execute updated `all_mappings.kql` against cluster

## Helper Scripts

**`check_missing_fields.py`** - Tries to validates field completeness by comparing sample data against KQL mappings using heuristics. 

```bash
python3 helper_scripts/check_missing_fields.py
# Custom paths: python3 helper_scripts/check_missing_fields.py --samples data/samples.txt --mappings custom_mappings/
```

Reports missing/obsolete fields. Expected optional fields (auto-ignored): `timestamp`, `Upload.*`, dynamic parent fields (`EventData.*`, `System.*`)

**`generate_sample_data.kql`** - ADX query to extract sample Velociraptor events for validation

Run in Azure Data Explorer, adjust time filter (default: `ago(1h)`), save output as `samples.txt`

**`combine_mappings.sh`** - Merges all `mappings/*.kql` and `analysis/**/*.kql` files into `all_mappings.kql` for deployment

```bash
# Default: includes all mappings + all analysis files (including analysis/generated/)
./helper_scripts/combine_mappings.sh

# Exclude a subdirectory (repeatable)
./helper_scripts/combine_mappings.sh --exclude-dir analysis/generated

# Custom mappings directory
./helper_scripts/combine_mappings.sh --dir custom_mappings/

# List all artifact names found in mappings/ (requires //ARTIFACT: header in each file)
./helper_scripts/combine_mappings.sh --list-artifacts
```

**Flags:**

| Flag | Argument | Description |
|---|---|---|
| `-d`, `--dir` | `DIR` | Source directory for artifact mappings (default: `mappings/`) |
| `--exclude-dir` | `DIR` | Exclude a directory from processing; repeatable. Path relative to repo root (e.g. `analysis/generated`) |
| `--list-artifacts` | — | Print `//ARTIFACT:` names from `mappings/` and exit. Does not scan `analysis/`. |
| `-h`, `--help` | — | Print usage and exit |

**Notes:**
- `analysis/` is scanned **recursively** (includes subdirectories such as `analysis/generated/`). Use `--exclude-dir analysis/generated` to omit generated files.
- `mappings/` is scanned **non-recursively** (flat directory only).
- The output `all_mappings.kql` is always overwritten on each run.
- `--list-artifacts` does not apply `--exclude-dir` filtering (safe: `mappings/` has no subdirectories).

## Analysis Functions

Pre-built KQL functions for cross-artifact analysis. Located in `analysis/`. Deployed as part of `all_mappings.kql`.

### `WindowsSupertimeline` — `analysis/Windows.Supertimeline.Timeline.kql`

Unions ~40 Windows artifact tables into a single chronological timeline.

```kusto
WindowsSupertimeline(ago(7d), now())
WindowsSupertimeline(ago(7d), now(), targetHostname="DESKTOP-ABC")
WindowsSupertimeline(ago(7d), now(), filterEventCategory="Execution,Persistence")
WindowsSupertimeline(ago(7d), now(), filterUser="admin", filterDescription="mimikatz")
```

Parameters: `startTime`, `endTime`, `targetHostname`, `targetOrg`, `filterEventCategory`, `filterEventType`, `filterPath`, `filterUser`, `filterDescription`

Companion: `WindowsSupertimelineSchema()` — lists all EventCategory/EventType/SourceTable combinations.

### `WindowsPersistenceOverview` — `analysis/Windows.Persistence.Overview.kql`

Unions all persistence snapshot tables into a normalized view with automated suspicion flagging.

Sources: Autoruns, ScheduledTask, StartupItem, WMISubscription, WMIProvider, LocalAccount, LocalAdmin

```kusto
WindowsPersistenceOverview("DESKTOP-ABC")
WindowsPersistenceOverview("DESKTOP-ABC", filterType="ScheduledTask")
WindowsPersistenceOverview("DESKTOP-ABC", filterType="LocalAccount,LocalAdmin")
WindowsPersistenceOverview("", targetOrg="CaseOrg1")
```

Suspicion flags (in the `Suspicious` column): `Unsigned`, `NoMetadata`, `SuspiciousPath`, `EncodedCommand`, `LOLBin`, `WMISubscription`, `NonStandardTask`, `ElevatedUserPath`, `NeverLoggedIn`, `DisabledWithHash`

Companion: `WindowsPersistenceOverviewSchema()` — lists all PersistenceType values and their source tables.

### `ApplyTimelineBaseline` — `analysis/Windows.Supertimeline.Baseline.kql`

Post-processing invoke function for noise reduction on Supertimeline results. Adds an `IsBaseline` column; filter it out for a clean timeline. Rule data is stored in the ADX lookup table `BaselineRules`, populated separately from a private source — not included in this repo.

```kusto
// Materialise once, then apply filters cheaply on the cached result
.set stored_query_result Timeline_Host1 with (expiresAfter=7d) <|
    WindowsSupertimeline(datetime(2026-03-20), datetime(2026-03-27), targetHostname="HOST1")

// Noise-free view (baseline removed)
stored_query_result("Timeline_Host1") | invoke ApplyTimelineBaseline() | where not(IsBaseline)

// Complete raw view (no invoke = no filtering)
stored_query_result("Timeline_Host1") | order by EventTime asc
```

**Rule schema** (`BaselineRules` CSV columns):

| Column | Description | Valid values |
|---|---|---|
| `RuleId` | Unique integer | 1, 2, 3… |
| `RuleName` | Human-readable label | Any string |
| `Scope` | Target function | `Supertimeline` |
| `EventCategory` | Scoping filter | Empty = all categories |
| `EventType` | Scoping filter | Empty = all types |
| `Column1` | Primary match column | `Path`, `Description`, `Details`, `User`, `Hash`, `SourceArtifact` |
| `Mode1` | Primary match operator | `has`, `contains`, `==`, `startswith` |
| `Value1` | Primary match value | Any string |
| `Column2` | Second condition column (AND logic) | Same as Column1, or empty |
| `Mode2` | Second condition operator | Same as Mode1, or empty |
| `Value2` | Second condition value | Any string, or empty |
| `IsEnabled` | Toggle without deleting | `true`, `false` |

**Rule examples:**
```csv
RuleId,RuleName,Scope,EventCategory,EventType,Column1,Mode1,Value1,Column2,Mode2,Value2,IsEnabled
1,SRUM_svchost,Supertimeline,Execution,SRUMExecution,Path,has,svchost.exe,,,,true
2,Prefetch_System32,Supertimeline,Execution,PrefetchHit,Path,startswith,C:\Windows\System32\,,,,true
3,WinUpdate_Detail,Supertimeline,EventLog,EvtxEvent,Description,has,Windows Update,Details,has,WindowsUpdateClient,true
```

**Rule management helpers** (`analysis/Windows.Supertimeline.RuleHelpers.kql`):
- `TestBaselineRule("storedResult", "Path", "has", "svchost.exe", "Execution", "SRUMExecution")` — preview which rows a candidate rule would filter
- `BaselineRulesSummary()` — rule statistics by scope and column

**Loading rules from Azure Blob Storage** (Phase 2 deployment):
```kusto
.set-or-replace BaselineRules <|
externaldata(RuleId:int, RuleName:string, Scope:string, EventCategory:string, EventType:string,
             Column1:string, Mode1:string, Value1:string, Column2:string, Mode2:string,
             Value2:string, IsEnabled:bool)
[h@"https://yourstorage.blob.core.windows.net/rules/baseline_rules.csv;SAS_TOKEN"]
with (format="csv", ignoreFirstRecord=true)
```

### Materialising a session result (`stored_query_result`)

Run the expensive union once and query the cached result cheaply. Default expiry is 24h; use `expiresAfter` to extend up to 7 days.

```kusto
// Materialise — run once at start of investigation session (expires after 7 days)
.set stored_query_result Timeline_ComputerXY <|
    WindowsSupertimeline(datetime(2026-03-20), datetime(2026-03-26), targetHostname="ComputerXY")

// Query the cache (no table scans)
stored_query_result("Timeline_ComputerXY")
| where EventCategory == "Execution"
| order by EventTime asc

// List all stored results in the database
.show stored_query_results

// Drop when done
.drop stored_query_result Timeline_ComputerXY
```

Optional — add `distributed=true` for large results:
```kusto
.set stored_query_result Timeline_ComputerXY with (expiresAfter=7d, distributed=true) <|
    WindowsSupertimeline(...)
```

