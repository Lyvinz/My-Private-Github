AzureDiagnostics
| where TimeGenerated >= ago(30d)
| where Category == "NetworkSecurityGroupRuleCounter"
| project
    TimeGenerated,
    ResourceId = tolower(_ResourceId),
    RuleName = ruleName_s,
    MatchedConnections = matchedConnections_d
| take 20


        AzureDiagnostics
| where TimeGenerated >= ago(30d)
| where Category == "NetworkSecurityGroupRuleCounter"
| extend
    NSGId = tolower(trim(" ", tostring(_ResourceId))),
    RuleName = tolower(trim(" ", tostring(ruleName_s)))
| summarize
    CounterRecords = count(),
    ReportedMatches = sum(matchedConnections_d)
    by NSGId, RuleName
| order by CounterRecords desc



        AzureDiagnostics
| where TimeGenerated >= ago(30d)
| where Category == "NetworkSecurityGroupRuleCounter"
| where ruleName_s == "YOUR_RULE_NAME"
| project TimeGenerated, matchedConnections_d
| order by TimeGenerated asc
| take 30
