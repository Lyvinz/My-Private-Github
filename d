# NSG Rule Counter and Hit Count Investigation

## 1. Objective

The purpose of this investigation was to compare configured Azure Network Security Group (NSG) rules against their corresponding rule-counter data in Azure Log Analytics.

The investigation aimed to identify rules with positive connection matches, rules reporting zero matches, and rules without available counter data.

## 2. Scope and Methodology

| Item | Details |
|---|---|
| Subscription | CF FCIB NON-PROD Data App |
| Log Analytics Workspace | `z-log-dat-shared-cac` |
| Log Table | `AzureDiagnostics` |
| Log Category | `NetworkSecurityGroupRuleCounter` |
| Observation Period | Last 30 days |
| NSGs Investigated | 24 |
| Configured Custom Rules | 246 |

Azure Resource Graph was used to retrieve the configured NSG rule inventory. The results were compared against Log Analytics rule-counter records using a combination of NSG resource ID and rule name.

The `UserRule_` prefix was removed from logged rule names during the Excel comparison to ensure consistency with the Resource Graph inventory.

## 3. KQL – Rule Hit Count Analysis

The following query was executed in the `z-log-dat-shared-cac` workspace to identify rules reporting positive or zero connection matches.

```kusto
AzureDiagnostics
| where TimeGenerated >= ago(30d)
| where Category == "NetworkSecurityGroupRuleCounter"
| where ruleName_s startswith "UserRule_"
| summarize
    PositiveRecords = countif(matchedConnections_d > 0),
    TotalReportedMatches = sum(matchedConnections_d)
    by _ResourceId, ruleName_s
| extend HitStatus = iff(
    PositiveRecords > 0,
    "POSITIVE MATCHES",
    "ZERO MATCHES"
)
| summarize RuleCount = count() by HitStatus
```

The results were reconciled with the configured rule inventory.

## 4. Investigation Findings

### 4.1 Overall Hit Count Results

| Classification | Rules | Percentage |
|---|---:|---:|
| Positive matches observed | 6 | 2.4% |
| Counter records present, zero matches | 85 | 34.6% |
| No counter data observed | 155 | 63.0% |
| **Total configured rules** | **246** | **100%** |

Of the 246 configured custom NSG rules, only six reported positive connection matches during the observation period.

A further 85 rules generated counter records but reported zero matches, while 155 rules had no matching counter records in the queried workspace.

### 4.2 Rule-Level Validation

A targeted investigation was performed against `z-nsg-dataeng_main-dev-cac-network`.

| Rule | Finding |
|---|---|
| `200-Inbound-allow-bastion` | 13 positive counter records, with 13 total reported matches |
| `285-Inbound-allow-vm-to-apim` | Counter records present, all reporting zero matches |
| `330-Inbound-allow-sql-to-datavm` | No matching counter records observed |

For this NSG, 34 configured rules were identified: one with positive matches, 30 with zero reported matches, and three without counter data.

Rule 330's source Application Security Group (ASG) also had no associated network interfaces during inspection. This may explain the absence of matching traffic, but does not establish the cause of missing counter records.

### 4.3 Key Finding

The investigation established three distinct conditions:

- **Positive matches:** Counter records confirm reported rule matches.
- **Zero matches:** Counter records exist, but no positive matches were reported.
- **No counter data:** No matching records were available to determine hit activity.

Therefore, counter-record presence cannot automatically be interpreted as rule usage, and missing counter records cannot be interpreted as proof of inactivity.

## 5. Limitations

- **Retention:** The investigated `AzureDiagnostics` table retains 30 days of data, limiting historical analysis.
- **Missing records:** The cause of absent counter data was not conclusively established for all 155 rules.
- **Traffic visibility:** The analysis reflects reported rule matches, not a complete assessment of application dependencies or all network traffic.
- **Diagnostic configuration:** Additional validation may be necessary to determine whether missing data relates to collection, delivery, or other factors.
- **Flow-log deployment:** A separate Network Watcher naming mismatch affected a flow-log deployment attempt. This was not established as the cause of missing rule-counter records.

## 6. Recommendations

1. Review the diagnostic settings and log delivery configuration for NSGs without observed counter records.
2. Use positive, zero, and unavailable counter-data classifications when assessing NSG rule activity.
3. Investigate zero-match rules further before considering changes, accounting for application dependencies and expected traffic patterns.
4. Consider a longer observation period where available to account for infrequent or scheduled traffic.

## 7. Conclusion

The investigation identified 246 configured custom NSG rules across 24 NSGs, with only six rules reporting positive connection matches during the available 30-day period.

The findings demonstrated that configured rule counts, counter-record availability, and positive connection matches represent different measurements.

The research successfully quantified the observed discrepancy and established a more accurate method of interpreting NSG hit count information. Further diagnostic validation is recommended for rules without available counter data before drawing conclusions about their usage or redundancy.
