# Incident 001: Multiple Failed Interactive Logons

## Incident Summary

Microsoft Sentinel generated a Medium-severity incident after the custom Multiple Failed Interactive Logons analytics rule detected five failed Windows authentication attempts on the lab endpoint.

- **Incident:** Multiple Failed Interactive Logons
- **Severity:** Medium
- **Status:** Closed
- **Affected Host:** `SOC-LAB-01`
- **Source IP:** `127.0.0.1`
- **Windows Event ID:** 4625
- **Logon Type:** 2: Interactive
- **MITRE ATT&CK:** T1110: Brute Force
- **Final Classification:** Benign Positive
- **Escalation:** Not required

## Alert Validation

I reviewed the underlying Windows Security Event telemetry to confirm that the alert represented actual authentication activity.

The investigation identified five Event ID 4625 failed interactive logon attempts on `SOC-LAB-01` within a short period.

The events were associated with:

- Host: `SOC-LAB-01`
- Source IP: `127.0.0.1`
- Logon Type: 2
- Event ID: 4625

This confirmed that the custom analytics rule triggered on the behavior it was designed to detect.

## Investigation

I reviewed the Microsoft Sentinel incident and its mapped entities to identify the affected host and source IP.

I then used KQL to review the underlying failed authentication events and surrounding authentication activity.

The investigation found:

1. Five failed interactive logon attempts occurred within a short period.
2. All identified failed attempts were associated with the same lab endpoint.
3. The source address was `127.0.0.1`, indicating local loopback activity rather than a remote source.
4. Successful local authentication activity was observed shortly after the failed attempts.
5. No evidence of a remote source or broader affected systems was identified during triage.

## Analyst Assessment

The alert was valid because the authentication failures matched the conditions defined in the analytics rule.

However, the activity was generated intentionally as part of controlled lab testing and did not represent malicious authentication activity.

The incident was therefore classified as a **Benign Positive**.

This distinction is important: the detection operated correctly, but investigation determined that the detected behavior was expected and non-malicious.

## Response and Disposition

I documented the investigation findings in the Sentinel activity log and determined that escalation was not required.

The incident was closed with:

- **Classification:** Benign Positive
- **Reason:** Suspicious but expected
- **Escalation:** None

## SOC Workflow Demonstrated

This incident exercised the following Tier 1 SOC workflow:

**Alert received → Incident ownership → Triage → Event validation → Entity review → Authentication analysis → Scope assessment → Analyst documentation → Classification → Closure**

## Lessons Learned

This investigation demonstrated the importance of validating alerts against the underlying telemetry before determining whether activity is malicious.

Repeated authentication failures can resemble brute-force behavior, but surrounding context, such as the source address, affected host, authentication type, and subsequent activity, is necessary to determine the appropriate disposition.
