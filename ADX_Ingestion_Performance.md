# ADX Ingestion Performance Commands

Run these against your ADX cluster/database to reduce ingestion latency for `RawVelociraptorEvents`.

## 1. Enable Streaming Ingestion

Low-latency ingestion path (bypasses the batching stage entirely for small payloads).

> Requires streaming ingestion to be enabled at the **cluster level** (Azure Portal → Cluster → Configurations → Streaming ingestion: On).

```kql
.alter table RawVelociraptorEvents policy streamingingestion enable
```

## 2. Reduce Batch Ingestion Window

Shortens the default 5-minute batching window to 30 seconds so bulk uploads are visible faster.

```kql
.alter table RawVelociraptorEvents policy ingestionbatching @'{"MaximumBatchingTimeSpan":"00:00:30","MaximumNumberOfItems":500,"MaximumRawDataSizeMB":1024}'
```

## 3. Increase Query Result Limits

By default ADX caps query results at 500k records and 64 MB. During large investigations (supertimeline over long periods, bulk exports) these limits cause truncated results. Relax them on the default workload group.

**Raise record limit to 2 million rows:**
```kql
.alter-merge workload_group default '{"RequestLimitsPolicy": {"MaxResultRecords": {"IsRelaxable": true, "Value": 2000000}}}'
```

**Remove record cap and raise byte limit to 2 GB:**
```kql
.alter-merge workload_group default '{"RequestLimitsPolicy":{"MaxResultBytes":{"IsRelaxable":true,"Value":2073741824},"MaxResultRecords":{"IsRelaxable":true,"Value":null}}}'
```

**Raise byte limit to 5 GB (for very large exports):**
```kql
.alter-merge workload_group default '{"RequestLimitsPolicy": {"MaxResultBytes": {"IsRelaxable": true, "Value": 5368709120}}}'
```

> `IsRelaxable: true` means individual queries can override the limit downward with `set maxmemoryconsumptionperiterator`. Setting `Value: null` removes that dimension of the cap entirely.

## Notes

- Use **streaming** for real-time Velociraptor live-collection feeds (low volume, low latency).
- Use **batching policy** for bulk/historical imports where you just want results sooner than 5 min.
- Both can be active simultaneously; ADX will use streaming for small payloads and fall back to batching for large ones.
- Apply result limit changes cluster-wide with caution — large result sets increase memory pressure on query nodes.
