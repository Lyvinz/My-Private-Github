Resources
| where type =~ "microsoft.network/networksecuritygroups"
| summarize TotalNSGs = count()
