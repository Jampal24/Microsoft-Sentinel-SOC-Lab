# Multiple Failed Interactive Logons

## Overview

This detection identifies repeated failed Windows authentication attempts that may indicate password guessing or brute-force activity.

The rule monitors Windows Security Event ID 4625 and generates a result when five or more failed logon attempts are observed for the same host, source IP address, and logon type.

## Detection Details

- **Platform:** Microsoft Sentinel
- **Data Source:** Windows Security Events
- **Event ID:** 4625: An account failed to log on
- **Severity:** Medium
- **MITRE ATT&CK Tactic:** Credential Access
- **MITRE ATT&CK Technique:** T1110: Brute Force
- **Threshold:** 5 or more failed logon attempts
- **Rule Frequency:** Every 5 minutes
- **Lookback Period:** 5 minutes

## Detection Logic

The KQL query:

1. Filters Windows Security Events for Event ID 4625.
2. Groups failed attempts by computer, source IP address, and logon type.
3. Counts the number of failed authentication attempts.
4. Returns groups containing five or more failures.
5. Uses the most recent failed attempt as the detection timestamp.

The KQL used by this detection is available in:

`../kql/failed-logon-detection.kql`

## Entity Mapping

The analytics rule maps the following Microsoft Sentinel entities:

- **Host:** `Computer`
- **IP Address:** `IpAddress`

These mappings allow Sentinel to associate the alert with the affected host and source IP during incident investigation.

## Alert and Incident Configuration

The scheduled analytics rule:

- Runs every 5 minutes.
- Searches the previous 5 minutes of security telemetry.
- Generates an alert when the detection query returns a result.
- Groups query results into a single alert.
- Creates Microsoft Sentinel incidents from generated alerts.
- Groups related alerts when all mapped entities match.

## Validation

The detection was validated by generating five controlled failed interactive logon attempts on the Windows lab endpoint.

Microsoft Sentinel successfully:

1. Ingested the resulting Event ID 4625 records.
2. Detected the authentication pattern using the custom analytics rule.
3. Generated a Medium-severity alert.
4. Created an incident containing the mapped Host and IP entities.

The resulting incident was subsequently investigated and documented as part of the SOC triage workflow.
