# Microsoft Sentinel SOC Lab Architecture

## Overview

This lab was built to create an end-to-end Microsoft Sentinel detection and incident triage environment using a Windows 11 endpoint.

The environment collects Windows Security Event telemetry from a physical Windows endpoint, sends the events to Azure Log Analytics, and uses Microsoft Sentinel for detection, alerting, and incident investigation.

## Architecture

```text
SOC-LAB-01 (Windows 11 Pro)
        |
        | Windows Security Events
        v
Azure Monitor Agent (AMA)
        |
        | Data Collection Rule
        v
Log Analytics Workspace
(law-sentinel-soc-lab)
        |
        v
Microsoft Sentinel
        |
        +--> KQL Analysis
        |
        +--> Scheduled Analytics Rule
        |
        +--> Alert
        |
        +--> Incident
        |
        v
Tier 1 SOC Triage
```

## Components

### Windows Endpoint

`SOC-LAB-01` is a physical Windows 11 Pro endpoint used to generate and collect Windows Security Event telemetry.

The endpoint was onboarded to Azure using Azure Arc.

### Azure Monitor Agent

Azure Monitor Agent (AMA) collects Windows Security Events from the endpoint.

A Data Collection Rule controls which telemetry is sent to the Log Analytics workspace.

### Log Analytics

The Log Analytics workspace `law-sentinel-soc-lab` stores the collected security telemetry and provides the data queried using KQL.

### Microsoft Sentinel

Microsoft Sentinel provides the SIEM capabilities used in the project, including:

- Security event analysis
- KQL querying
- Scheduled analytics rules
- MITRE ATT&CK mapping
- Entity mapping
- Alert generation
- Incident creation and investigation
- Incident classification and closure

## Detection Workflow

The completed workflow for the failed-logon scenario was:

**Windows authentication activity → Windows Security Event 4625 → Azure Monitor Agent → Log Analytics → KQL detection → Microsoft Sentinel analytics rule → Alert → Incident → Tier 1 investigation → Benign Positive classification → Incident closure**

## Lab Scope

This environment is a controlled cybersecurity lab intended for hands-on learning and portfolio development.

The authentication activity used to validate the detection was intentionally generated on the lab endpoint. No external systems or unauthorized targets were involved.
