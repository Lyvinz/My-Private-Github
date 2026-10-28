
search in (*) "z-nsg-dataeng_main-dev-cae-network"
| where TimeGenerated > ago(90d)
| summarize Records = count() by $table
| order by Records desc
