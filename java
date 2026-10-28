
Resources
| where type =~ "microsoft.network/networksecuritygroups"
| mv-expand rule = properties.securityRules
| extend Priority = toint(rule.properties.priority)
| where Priority < 65000
| project
    NSGId = tolower(id),
    NSG = name,
    RuleName = tolower(tostring(rule.name)),
    Direction = tostring(rule.properties.direction),
    Priority
| order by NSG asc, Priority asc


    
AzureDiagnostics
| where TimeGenerated > ago(24h)
| where Category == "NetworkSecurityGroupRuleCounter"
| where OperationName == "NetworkSecurityGroupCounters"
| where ruleName_s startswith "UserRule_"
| extend
    NSGId = tolower(tostring(_ResourceId)),
    RuleName = tolower(substring(ruleName_s, 9))
| summarize
    Hits = sum(tolong(matchedConnections_d)),
    Records = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by NSGId, NSG = Resource, RuleName
| project NSGId, NSG, RuleName, Hits,
          Records, FirstSeen, LastSeen
| order by NSG asc, RuleName asc


 =LOWER(TRIM(A2))&"|"&LOWER(TRIM(C2))


=LOWER(TRIM(A2))&"|"&LOWER(TRIM(C2))

=IF(COUNTIF('Log Analytics'!$H:$H,F2)>0,"COUNTER PRESENT","NO COUNTER DATA")
=IF(G2="NO COUNTER DATA","",SUMIF('Log Analytics'!$H:$H,F2,'Log Analytics'!$D:$D))


=COUNTA(C2:C247)
=COUNTIF(G2:G247,"COUNTER PRESENT")
=COUNTIF(G2:G247,"NO COUNTER DATA")
=COUNTIFS(G2:G247,"COUNTER PRESENT",H2:H247,">0")
=COUNTIFS(G2:G247,"COUNTER PRESENT",H2:H247,0)
