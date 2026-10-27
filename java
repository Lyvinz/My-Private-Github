
AzureDiagnostics
| where TimeGenerated > ago(24h)
| where Category == "NetworkSecurityGroupRuleCounter"
| where OperationName == "NetworkSecurityGroupCounters"
| where Resource =~ "Z-NSG-DATAENG_MAIN-DEV-CAC-NETWORK"
| summarize
    Records = count(),
    TotalHits = sum(matchedConnections_d)
    by RuleName = ruleName_s
| order by RuleName asc
