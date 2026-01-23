# Velociraptor Artefact KQL Mappings

KQL (Kusto Query Language) mappings for ingesting and processing Velociraptor artefact data into Azure Data Explorer (Kusto).

## Overview

This project provides table schemas, routing functions, and update policies to automatically parse Velociraptor artefact data from a raw ingestion table into structured, artifact-specific tables for incident response and forensic analysis.

## Structure

- **`raw_velociraptor_events.kql`** - Creates the `RawVelociraptorEvents` ingestion table (run first)
- **`mappings/`** - Individual KQL mapping files for each Velociraptor artifact
- **`combine_mappings.sh`** - Script to merge all mappings into a single file
- **`all_mappings.kql`** - Generated combined file (execute this against your cluster)

## Current Parsed Artifacts

- `Generic.Applications.Chrome.SessionStorage` - Browser session storage entries
- `Generic.Applications.Office.Keywords` - Office document keyword hits with context
- `Generic.Client.DiskSpace` - Volume capacity and free space
- `Generic.Client.DiskUsage` - Directory size summary
- `Generic.Client.Info/WindowsInfo` - Windows system information
- `Generic.Client.Info/BasicInformation` - Client metadata and configuration
- `Generic.Detection.HashHunter` - File hashes with timestamps
- `Generic.Network.InterfaceAddresses` - Interface IP/MAC/flags
- `Generic.System.EfiSignatures/Certificates` - EFI trust store certificates
- `Generic.System.EfiSignatures/Hashes` - EFI dbx hashes
- `Generic.System.Pstree` - Process tree and hierarchy data
- `Network.ExternalIpAddress` - Observed public IP
- `System.VFS.DownloadFile` - Downloaded file metadata
- `System.VFS.ListDirectory/Listing` - File and registry directory listings
- `System.VFS.ListDirectory/Stats` - Listing pagination stats
- `Windows.Analysis.EvidenceOfDownload` - Zone.Identifier download evidence
- `Windows.EventLogs.Evtx` - Windows event log records
- `Windows.Forensics.Lnk` - Shortcut evidence
- `Windows.Forensics.Prefetch` - Prefetch execution metadata

### Adding New Artifacts

Each artifact mapping requires three components:
1. **`.create table`** - Define the schema with typed columns
2. **`.create-or-alter function`** - Extract and transform fields from `RawData`
3. **`.alter table policy update`** - Auto-route matching events to the table

## Usage

1. **First time only:** Create the raw ingestion table by executing `raw_velociraptor_events.kql` against your cluster

2. Generate the combined mappings file:
   ```bash
   ./combine_mappings.sh
   # Or specify a custom directory: ./combine_mappings.sh -d custom_dir
   ```

3. Execute `all_mappings.kql` against your Azure Data Explorer cluster

4. Ingest Velociraptor data to the `RawVelociraptorEvents` table - data will automatically route to artifact-specific tables