AzureDiagnostics
| where TimeGenerated >= ago(30d)
| where Category == "NetworkSecurityGroupRuleCounter"
| where _ResourceId contains "z-nsg-dataeng_main-dev-cac-network"
| where ruleName_s contains "285-inbound"
    or ruleName_s contains "290-inbound"
| summarize
    CounterRecords = count(),
    ZeroRecords = countif(matchedConnections_d == 0),
    PositiveRecords = countif(matchedConnections_d > 0),
    LastSeen = max(TimeGenerated)
    by ruleName_s
