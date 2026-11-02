AzureDiagnostics
| where TimeGenerated >= ago(30d)
| where Category == "NetworkSecurityGroupRuleCounter"
| where _ResourceId has "z-nsg-api_mgmt_subnet-dev-cac-network"
| summarize
    CounterRecords = count(),
    PositiveRecords = countif(matchedConnections_d > 0),
    LastRecord = max(TimeGenerated)
    by _ResourceId
