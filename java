
AzureDiagnostics
| where TimeGenerated > ago(24h)
| where Category == "NetworkSecurityGroupRuleCounter"
| where OperationName == "NetworkSecurityGroupCounters"
| where ruleName_s startswith "UserRule_"
| summarize
    RulesReporting = dcount(ruleName_s),
    TotalHits = sum(matchedConnections_d),
    LastRecorded = max(TimeGenerated)
    by NSG = Resource
| order by NSG asc



    
Resources
| where type =~ "microsoft.network/networksecuritygroups"
| mv-expand rule = properties.securityRules
| summarize ConfiguredRules = count()
    by NSG = name, ResourceGroup = resourceGroup
| order by NSG asc
