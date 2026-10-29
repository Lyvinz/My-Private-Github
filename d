AzureDiagnostics
| where TimeGenerated >= ago(30d)
| where Category in (
    "NetworkSecurityGroupRuleCounter",
    "NetworkSecurityGroupEvent"
)
| where _ResourceId has "z-nsg-dataeng_main-dev-cae-network"
| summarize Records = count(), LastSeen = max(TimeGenerated)
    by Category
