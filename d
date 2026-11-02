
AzureDiagnostics
| where TimeGenerated >= ago(30d)
| where Category == "NetworkSecurityGroupRuleCounter"
| extend NSG = extract(
    @"(?i)/networksecuritygroups/([^/]+)",
    1,
    _ResourceId
)
| extend Region = case(
    NSG contains "-cac-", "Canada Central",
    NSG contains "-cae-", "Canada East",
    "Unknown"
)
| summarize
    NSGsReporting = dcount(_ResourceId),
    CounterRecords = count(),
    PositiveRecords = countif(matchedConnections_d > 0)
    by Region
| order by Region asc
