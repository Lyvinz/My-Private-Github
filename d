AzureDiagnostics
| where TimeGenerated >= ago(30d)
| where Category == "NetworkSecurityGroupRuleCounter"
| where _ResourceId has "z-nsg-dataeng_main-dev-cac-network"
| where ruleName_s contains "290-inbound"
| project TimeGenerated, ruleName_s, matchedConnections_d
| order by TimeGenerated desc
