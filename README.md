# Microsoft Sentinel – Identity Brute Force Detection Lab

## Overview
This lab demonstrates how to configure Microsoft Sentinel to detect potential identity brute-force attacks against Azure Active Directory (Entra ID) accounts. The detection is based on analyzing Azure AD sign-in logs using KQL and creating a scheduled analytics rule that generates incidents when multiple failed sign-in attempts occur within a short time window.

This project simulates real-world SOC workflows including detection engineering, alert validation, incident investigation, and incident closure.

---

## Objectives
- Enable Microsoft Sentinel in an Azure Log Analytics Workspace
- Ingest Azure AD Sign-In Logs
- Create test users to simulate failed authentication attempts
- Write and validate KQL queries for failed sign-ins
- Create a Sentinel analytics rule for identity brute-force detection
- Generate and investigate a Sentinel incident
- Document findings and close the incident

---

## Tools & Technologies
- Microsoft Azure
- Microsoft Sentinel
- Azure Active Directory (Entra ID)
- Log Analytics Workspace
- Kusto Query Language (KQL)

---

## Lab Architecture
- Azure Log Analytics Workspace with Microsoft Sentinel enabled
- Azure AD Sign-In Logs as the primary data source
- Scheduled analytics rule triggering incidents
- Sentinel incident investigation dashboard

---

## Step 1: Enable Microsoft Sentinel
Microsoft Sentinel was enabled on a dedicated Log Analytics Workspace.

📸 **Screenshot:** Sentinel enabled on Log Analytics Workspace  
![Sentinel Enabled](screenshots/01-sentinel-enabled.png)

---

## Step 2: Connect Azure AD Sign-In Logs
The Azure Active Directory data connector was enabled to ingest sign-in logs.

📸 **Screenshot:** Azure AD data connector  
![Data Connector](screenshots/02-data-connector.png)

---

## Step 3: Create Test Users
Test users were created in Azure AD to simulate failed authentication attempts.

📸 **Screenshot:** Test user creation  
![Create Users](screenshots/04-create-test-users.png)

---

## Step 4: Simulate Failed Sign-Ins
Multiple failed sign-in attempts were generated against the test user account to simulate a brute-force attack.

📸 **Screenshot:** Failed sign-in activity  
![Failed Sign-ins](screenshots/05-failed-logins.png)

---

## Step 5: Query Sign-In Logs with KQL
KQL was used to identify repeated failed sign-in attempts.

```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != 0
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress
| where FailedAttempts > 3
```

---

## Step 6: Create Analytics Rule
A scheduled analytics rule was created in Microsoft Sentinel using the validated KQL query to detect identity brute-force activity.

**Rule Configuration Details:**
- Rule type: Scheduled
- Severity: Medium
- Query frequency: Every 5 minutes
- Lookup period: Last 1 hour
- Alert threshold: Greater than 0 results
- Incident creation: Enabled
- Alert grouping: Enabled to group related alerts into a single incident

📸 **Screenshot:** Analytics rule configuration  
![Analytics Rule Configuration](screenshots/07-create-analytics-rule.png)

---

## Step 7: Generate Sentinel Incident
After triggering multiple failed sign-in attempts against the test user account, Microsoft Sentinel automatically generated an incident based on the analytics rule.

The incident aggregated failed authentication events into a single case for investigation.

📸 **Screenshot:** Sentinel incident generated  
![Incident Generated](screenshots/08-incident-generated.png)

---

## Step 8: Incident Investigation
The incident was investigated by reviewing:
- Azure AD sign-in logs
- UserPrincipalName associated with failed attempts
- Source IP address
- Application used during authentication attempts
- Result descriptions indicating invalid credentials

KQL was used during investigation to confirm the scope and frequency of failed authentication attempts.

📸 **Screenshot:** Incident investigation with logs  
![Incident Investigation](screenshots/09-incident-investigation.png)

---

## Step 9: Analyst Notes and Validation
Analyst notes were added to document findings and confirm the incident as a true positive identity brute-force attempt.

The investigation confirmed:
- Multiple failed sign-in attempts
- Single target user
- No successful authentication observed

📸 **Screenshot:** Analyst comments and evidence  
![Analyst Notes](screenshots/10-analyst-notes.png)

---

## Step 10: Incident Closure
After completing the investigation, the incident was closed with the classification **True Positive – Suspicious Activity**.

This completed the SOC workflow from detection to resolution.

📸 **Screenshot:** Incident closed  
![Incident Closed](screenshots/11-incident-closed.png)

---

## Key Takeaways
- Microsoft Sentinel can effectively detect identity-based attacks using Azure AD telemetry
- KQL enables precise detection engineering for authentication threats
- Analytics rules automate alerting and incident creation
- This lab mirrors real-world SOC analyst investigation and response workflows

---

## Future Improvements
- Implement automated responses using Logic Apps
- Add password spray detection rules
- Add MFA-related detections and impossible travel alerts

---

## Author
**Levi Hill**  
