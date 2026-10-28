
AzureDiagnostics
| where TimeGenerated >= ago(30d)
| where Category == "NetworkSecurityGroupRuleCounter"
| where Resource =~ "z-nsg-ingress_appgw-dev-cac-network"
| summarize
    CounterRecords = count(),
    TotalHits = sum(matchedConnections_d),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by ruleName_s
| order by ruleName_s asc



      
AzureDiagnostics
| where TimeGenerated >= ago(1d)
| where Category == "NetworkSecurityGroupRuleCounter"
| where Resource =~ "z-nsg-ingress_appgw-dev-cac-network"
| where ruleName_s startswith "UserRule_"
| project
    TimeGenerated,
    ruleName_s,
    matchedConnections_d,
    macAddress_s,
    _ResourceId
| order by TimeGenerated desc
| take 30



        
AzureDiagnostics
| where TimeGenerated >= ago(30d)
| where Category == "NetworkSecurityGroupRuleCounter"
| summarize
    CounterRecords = count(),
    RulesObserved = dcount(ruleName_s),
    TotalHits = sum(matchedConnections_d)
    by NSG = Resource
| order by NSG asc
