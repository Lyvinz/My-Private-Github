AzureDiagnostics
| where TimeGenerated > ago(30d)
| where Category == "NetworkSecurityGroupRuleCounter"
| extend NSG = tolower(Resource)
| summarize
    CounterRecords = count(),
    TotalHits = sum(matchedConnections_d)
    by NSG, ruleName_s
| order by NSG asc, ruleName_s asc
