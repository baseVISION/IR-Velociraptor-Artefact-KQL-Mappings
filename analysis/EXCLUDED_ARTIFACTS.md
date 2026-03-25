# Artifacts Excluded from WindowsNormalizedTimeline

These artifacts have mapping files but are excluded from the supertimeline because
their timestamps do not represent forensic event times. They are grouped below for
future dedicated functions (e.g., `WindowsSystemSnapshot()`, `WindowsCollectionMeta()`).

---

## Snapshot Artifacts (point-in-time system state)

These capture system state at collection time. Useful for baseline comparisons
and context, but timestamps only reflect when Velociraptor ran the collection.

| Table | Source File | What it captures |
|---|---|---|
| WindowsNetworkArpCache | Windows.Network.ArpCache.kql | ARP table — IP-to-MAC mappings |
| WindowsNetworkInterfaceAddresses | Windows.Network.InterfaceAddresses.kql | Network interface IPs and aliases |
| WindowsNetworkListeningPorts | Windows.Network.ListeningPorts.kql | Processes bound to network ports |
| WindowsNetworkNetstat | Windows.Network.Netstat.kql | Active TCP/UDP connections |
| WindowsNetworkNetstatEnriched | Windows.Network.NetstatEnriched.kql | Enriched netstat with geolocation |
| WindowsNetworkNetstatEnrichedNetstat | Windows.Network.NetstatEnriched.kql | Raw netstat source for enrichment |
| WindowsSysFirewallRules | Windows.Sys.FirewallRules.kql | Firewall rules and policy |
| WindowsSysInterfaces | Windows.Sys.Interfaces.kql | Network adapter properties |
| WindowsSysStartupItems | Windows.Sys.StartupItems.kql | Startup programs (registry/folders) |
| WindowsSystemLocalAdmins | Windows.System.LocalAdmins.kql | Local administrator group members |
| WindowsSystemShares | Windows.System.Shares.kql | SMB network shares |
| WindowsSystemWMIProviders | Windows.System.WMIProviders.kql | Installed WMI providers |
| WindowsDetectionBinaryHunter | Windows.Detection.BinaryHunter.kql | Suspicious/unsigned binaries scan |
| WindowsDetectionMutantsHandles | Windows.Detection.Mutants.kql | Kernel mutex handles |
| WindowsDetectionMutantsObjectTree | Windows.Detection.Mutants.kql | Kernel object tree enumeration |
| WindowsForensicsPartitionTable | Windows.Forensics.PartitionTable.kql | Disk partition layout |
| WindowsForensicsUEFI | Windows.Forensics.UEFI.kql | UEFI firmware file inventory |

---

## Velociraptor Collection / Operational Artifacts

These are metadata about the collection process itself, not forensic events
from the endpoint.

| Table | Source File | What it captures |
|---|---|---|
| WindowsCollectorsFileAllMatchesMetadata | Windows.Collectors.File.kql | File collection search glob matches |
| WindowsCollectorsFileUploads | Windows.Collectors.File.kql | Uploaded file tracking metadata |
| WindowsEventLogsHayabusaUpload | Windows.EventLogs.Hayabusa.kql | Hayabusa rule archive upload |
| WindowsForensicsFilenameSearch | Windows.Forensics.FilenameSearch.kql | Filename keyword search results |
| WindowsTriageTargetsSearchGlobs | Windows.Triage.Targets.kql | Triage collection glob patterns |
| WindowsTriageTargetsUploads | Windows.Triage.Targets.kql | Triage uploaded files metadata |
| WindowsTriageTargetsAllMatchesMetadata | Windows.Triage.Targets.kql | Triage file match results |
| WindowsTriageTargetsPrefetchBinariesExecutables | Windows.Triage.Targets.kql | Triage prefetch binary analysis |

---

## Excluded from Supertimeline (timestamp issues)

These have mapping files and contain useful data, but their timestamp doesn't
represent a distinct forensic event time.

| Table | Reason | Notes |
|---|---|---|
| WindowsPacksPersistenceStartupItems | Collection time only | No forensic timestamp available |
| WindowsPacksPersistenceWMIEventFilters | Collection time only | No forensic timestamp available |
| WindowsSystemPowershellPSReadline | File-level Mtime | All commands share one timestamp (history file Mtime) |

---

## Borderline / Future Consideration

These have some timestamp value but are either redundant, very high volume,
or use file metadata timestamps rather than event times.

| Table | Timestamp Source | Notes |
|---|---|---|
| WindowsRegistryNTUser | Registry key Mtime | Forensically valid but extremely high volume — every registry key |
| WindowsSystemWMIQuery | WMI CreationDate | Process creation via WMI — partially redundant with Pslist |
| WindowsSystemPowershellModuleAnalysisCache | Cache Timestamp | Module analysis time — some forensic value |
| WindowsAttackPrefetch | Prefetch file ModTime | Redundant with existing Prefetch timeline legs |
| WindowsDetectionBinaryRename | File Mtime | Renamed binary write time — file metadata, not event |
| WindowsNTFSADSHunter | Host file SI Mtime | ADS host file modification time |
| WindowsNTFSMFT | SI LastModified | Raw MFT — already covered by WindowsTimelineMFT |
