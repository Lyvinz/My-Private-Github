Flow 1 – Remediation Plan / SLA List Update

Purpose:
Automatically populate and update the SLA tracking list using information from the Remediation Plan List.

Trigger:
SharePoint – When an item is created or modified

Process:

The flow triggers when a remediation plan record is created or updated.
It retrieves the corresponding record from the SLA tracking list.
It checks whether the record already exists.
If the record exists, Update item is used to update it.
If the record does not exist, Create item is used to create a new SLA tracking record.
The relevant remediation information is transferred to the SLA tracking list, including:
Application
Vulnerability ID
Severity
CVSS Score
Owner
Date Identified
SLA Deadline
Target Completion Date
Status
Date Remediated
MTTR

SLA Deadline Logic:

Critical = Date Identified + 30 days
High = Date Identified + 60 days
Medium = Date Identified + 120 days
Flow 2 – Daily SLA Status Update

Purpose:
Automatically recalculate Days to SLA and update SLA Status each day.

Trigger:
Power Automate Recurrence – Daily at 8:00 AM

Process:

Get items retrieves records from the SLA tracking list.
For each processes each record.
The flow checks that an SLA Deadline exists.
Compose – Days to SLA calculates the number of days between the current date and the SLA Deadline.
The flow evaluates the calculated value using two conditions.
The corresponding Update item action updates Days to SLA and SLA Status.

SLA Status Logic:

Days to SLA	SLA Status
< 0	Breached
0–14	At Risk
> 14	Within SLA

Flow Logic:

Recurrence – Daily at 8:00 AM
        ↓
Get items
        ↓
For each item
        ↓
SLA Deadline populated?
        ↓
Calculate Days to SLA
        ↓
Days to SLA < 0?
   ├── Yes → Update Item → Breached
   │
   └── No → Days to SLA <= 14?
              ├── Yes → Update Item → At Risk
              │
              └── No → Update Item → Within SLA
Current Status

Both flows have been created and tested successfully. The SLA tracking list is being populated/updated, and the scheduled flow correctly updates Days to SLA and categorizes records as Within SLA, At Risk, or Breached.
