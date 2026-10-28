
AzureDiagnostics
| where TimeGenerated > ago(90d)
| where Category == "NetworkSecurityGroupRuleCounter"
| where ruleName_s startswith "UserRule_"
| extend NSG = tolower(Resource)
| extend RuleName = replace_regex(ruleName_s, @"^UserRule_[0-9]+-", "")
| summarize
    CounterRecords = count(),
    TotalHits = sum(matchedConnections_d),
    LastSeen = max(TimeGenerated)
    by NSG, RuleName
| order by NSG asc, RuleName asc
