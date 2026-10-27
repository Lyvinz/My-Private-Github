
AzureDiagnostics
| where TimeGenerated > ago(24h)
| where Category == "NetworkSecurityGroupRuleCounter"
| where OperationName == "NetworkSecurityGroupCounters"
| summarize
    HitCount = sum(matchedConnections_d),
    LastRecorded = max(TimeGenerated)
    by NSG = Resource, Rule = ruleName_s,
       Direction = direction_s, Action = type_s
| order by NSG asc, Rule asc


    
AzureDiagnostics
| where TimeGenerated > ago(24h)
| where Category == "NetworkSecurityGroupRuleCounter"
| where OperationName == "NetworkSecurityGroupCounters"
| where ruleName_s startswith "UserRule_"
| summarize
    HitCount = sum(matchedConnections_d),
    LastRecorded = max(TimeGenerated)
    by NSG = Resource,
       Rule = ruleName_s,
       Direction = direction_s,
       Action = type_s
| order by NSG asc, Rule asc
