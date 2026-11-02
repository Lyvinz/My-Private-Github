AzureDiagnostics
| where TimeGenerated >= ago(30d)
| where Category == "NetworkSecurityGroupRuleCounter"
| extend NSG = extract(
    @"/networkSecurityGroups/([^/]+)",
    1,
    _ResourceId
)
| summarize
    CounterRecords = count(),
    PositiveRecords = countif(matchedConnections_d > 0)
    by NSG
| order by NSG asc
