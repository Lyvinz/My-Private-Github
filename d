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
