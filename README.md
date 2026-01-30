# Velociraptor Artefact KQL Mappings

KQL mappings for parsing Velociraptor forensic artifacts into Azure Data Explorer tables. Automatically routes per artifacts from raw ingestion to structured tables.

> **Disclaimer:** This project covers a subset of available Velociraptor artifacts. Mappings are provided as-is and may contain errors. Always validate against your data before production use.


## Structure

- **`Ingress_Setup_RawVelociraptorEvents.kql`** - Creates the raw ingestion table (one-time setup)
- **`all_mappings.kql`** - Generated deployment artifact (execute against cluster)
- **`mappings/`** - Individual KQL files per artifact (table + routing function + update policy)
- **`helper_scripts/combine_mappings.sh`** - Merges all mappings into deployment file
- **`.github/.copilot-instructions.md`** - Development guidelines for creating new mappings

## Current Parsed Artifacts
- `Generic.Applications.Chrome.SessionStorage`
- `Generic.Applications.Office.Keywords`
- `Generic.Client.DiskSpace`
- `Generic.Client.DiskUsage`
- `Generic.Client.Info/WindowsInfo`
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
- `Windows.Detection.Amcache`
- `Windows.Detection.BinaryHunter`
- `Windows.Detection.BinaryRename`
- `Windows.Detection.Malfind`
- `Windows.Detection.Mutants/Handles`
- `Windows.EventLogs.Evtx`
- `Windows.EventLogs.Hayabusa/Results`
- `Windows.Forensics.CertUtil`
- `Windows.Forensics.Clipboard`
- `Windows.Forensics.Lnk`
- `Windows.Forensics.Prefetch`
- `Windows.Forensics.RecycleBin`
- `Windows.Forensics.SAM/CreateTimes`
- `Windows.Forensics.Shellbags`
- `Windows.Forensics.SRUM/Execution Stats`
- `Windows.Forensics.Timeline`
- `Windows.Forensics.Usn`
- `Windows.Network.ArpCache`
- `Windows.Network.InterfaceAddresses`
- `Windows.Network.ListeningPorts`
- `Windows.Network.Netstat`
- `Windows.Network.NetstatEnriched`
- `Windows.NTFS.ADSHunter`
- `Windows.NTFS.MFT`
- `Windows.Packs.LateralMovement/AlternateLogon`
- `Windows.Packs.Persistence/Startup Items`
- `Windows.Registry.NTUser`
- `Windows.Registry.ScheduledTasks`
- `Windows.Registry.UserAssist`
- `Windows.Sys.FirewallRules`
- `Windows.Sys.Interfaces`
- `Windows.Sysinternals.Autoruns`
- `Windows.Sys.StartupItems`
- `Windows.System.Amcache/InventoryApplicationFile`
- `Windows.System.AppCompatPCA`
- `Windows.System.LocalAdmins`
- `Windows.System.Powershell.ModuleAnalysisCache`
- `Windows.System.Powershell.PSReadline`
- `Windows.System.Pslist`
- `Windows.System.Shares`
- `Windows.System.WMIProviders`
- `Windows.System.WMIQuery`
- `Windows.Timeline.MFT`
- `Windows.Triage.Targets/SearchGlobs`

## Quick Start

1. **One-time setup:** Execute `Ingress_Setup_RawVelociraptorEvents.kql` against your Azure Data Explorer cluster
2. **Deploy mappings:** Execute `all_mappings.kql` against your cluster
3. **Ingest data:** Send Velociraptor output to `RawVelociraptorEvents` table
4. **Query:** Data automatically routes to artifact-specific tables (e.g., `WindowsForensicsPrefetch`, `LinuxSysPslist`)

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

**`combine_mappings.sh`** - Merges all `mappings/*.kql` files into `all_mappings.kql` for deployment

```bash
./helper_scripts/combine_mappings.sh
```

