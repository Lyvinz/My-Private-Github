Resources
| where type =~ "microsoft.network/networksecuritygroups"
| mv-expand Rule = properties.securityRules
| extend
    NSGId = tolower(id),
    NSGName = name,
    RuleName = tostring(Rule.name),
    Priority = toint(Rule.properties.priority)
| where Priority < 65000
| project NSGId, NSGName, RuleName, Priority
| order by NSGName asc, Priority asc



AzureDiagnostics
| where TimeGenerated >= ago(30d)
| where Category == "NetworkSecurityGroupRuleCounter"
| extend
    NSGId = tolower(trim(" ", tostring(_ResourceId))),
    RuleName = tolower(trim(" ", replace_regex(tostring(ruleName_s), @"^(?i:UserRule_)", "")))
| where ruleName_s startswith "UserRule_"
| summarize
    Records = count(),
    Hits = sum(matchedConnections_d),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by NSGId, RuleName
| order by NSGId asc
