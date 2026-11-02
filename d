Resources
| where type =~ "microsoft.network/networksecuritygroups"
| summarize TotalNSGs = count()
  
AzureDiagnostics
| where TimeGenerated >= ago(30d)
| where Category == "NetworkSecurityGroupRuleCounter"
| extend SubscriptionId = extract(
    @"(?i)/subscriptions/([^/]+)", 1, _ResourceId
)
| summarize NSGsReporting = dcount(_ResourceId)
    by SubscriptionId
