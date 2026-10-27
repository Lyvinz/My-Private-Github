
Resources
| where type =~ "microsoft.network/networksecuritygroups"
| where name =~ "z-nsg-dataeng_main-dev-cac-network"
| mv-expand rule = properties.securityRules
| project NSG = name,
          RuleName = tostring(rule.name),
          Priority = toint(rule.properties.priority)
| order by Priority asc


    
AzureDiagnostics
| where TimeGenerated > ago(24h)
| where Category == "NetworkSecurityGroupRuleCounter"
| where OperationName == "NetworkSecurityGroupCounters"
| where Resource =~ "Z-NSG-DATAENG_MAIN-DEV-CAC-NETWORK"
| where ruleName_s startswith "UserRule_"
| summarize HitCount = sum(matchedConnections_d)
    by RuleName = ruleName_s
| order by RuleName asc
