# Velociraptor Artefact KQL Mappings

KQL (Kusto Query Language) mappings for ingesting and processing Velociraptor artefact data into Azure Data Explorer (Kusto).

## Overview

This project provides table schemas, routing functions, and update policies to automatically parse Velociraptor artefact data from a raw ingestion table into structured, artifact-specific tables for incident response and forensic analysis.

## Features

- **Raw Event Ingestion**: Single `RawVelociraptorEvents` table with streaming ingestion enabled 
- **Automated Routing**: Update policies automatically route incoming data to artifact-specific tables
- **Structured Schemas**: Pre-defined schemas for common Velociraptor artifacts:
  - `Generic.Client.Info/WindowsInfo` - Windows system information
  - `Generic.Client.Info/BasicInformation` - Client metadata and configuration
  - `Generic.System.Pstree` - Process tree and hierarchy data

## Usage

1. Execute the KQL commands in [mappings.kql](mappings.kql) against your Azure Data Explorer cluster
2. Ingest Velociraptor data to the `RawVelociraptorEvents` table
3. Data will automatically be parsed and routed to the appropriate artifact tables