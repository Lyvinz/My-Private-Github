AzureDiagnostics
| where TimeGenerated > ago(30d)
| where tolower(_ResourceId) contains "/networksecuritygroups/z-nsg-dat_cai_ase_subnet-dev-cae-network"
| summarize
    Records = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Category
| order by Records desc


AzureDiagnostics
| where TimeGenerated > ago(30d)
| where tolower(_ResourceId) contains "/networksecuritygroups/z-nsg-dat_cai_ase_subnet-dev-cae-network"
| summarize Records = count() by bin(TimeGenerated, 1d), Category
| order by TimeGenerated asc

        AzureDiagnostics
| where TimeGenerated > ago(30d)
| where Category in (
    "NetworkSecurityGroupRuleCounter",
    "NetworkSecurityGroupEvent"
)
| summarize
    LastSeen = max(TimeGenerated),
    Records = count()
    by Resource
| order by LastSeen asc


Resources
| where type =~ "microsoft.network/networksecuritygroups"
| project
    NSGName = name,
    ResourceGroup = resourceGroup,
    Region = location,
    SubscriptionId = subscriptionId,
    ResourceId = id
| order by NSGName asc


        AzureDiagnostics
| where TimeGenerated > ago(30d)
| where Category == "NetworkSecurityGroupRuleCounter"
| extend NSG = toupper(Resource)
| summarize
    CounterRecords = count(),
    TotalHits = sum(matchedConnections_d),
    RulesObserved = dcount(ruleName_s),
    LastSeen = max(TimeGenerated)
    by NSG
| order by NSG asc

        AzureDiagnostics
| where TimeGenerated > ago(30d)
| where Category == "NetworkSecurityGroupRuleCounter"
| where Resource =~ "Z-NSG-INGRESS_APPGW-DEV-CAC-NETWORK"
| summarize
    Records = count(),
    TotalHits = sum(matchedConnections_d),
    LastSeen = max(TimeGenerated)
    by ruleName_s
| order by TotalHits desc


        AzureDiagnostics
| where TimeGenerated > ago(30d)
| where Category in (
    "NetworkSecurityGroupRuleCounter",
    "NetworkSecurityGroupEvent"
)
| summarize Records = count()
    by Resource, Category, bin(TimeGenerated, 1d)
| order by Resource asc, TimeGenerated asc
