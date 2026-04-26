# Validation Approach

The detections in this repository are drafts until they are validated.

For each rule, I want to capture:

- the data source and expected field names
- at least one event that should match
- at least one event that should not match
- the threshold or condition that decides the alert
- likely false positives
- triage steps after the alert fires

## Current limitation

Most rules are written as concept KQL. They are useful for showing detection thinking, but they should not be treated as production-ready content until they are run against a real Microsoft Sentinel, Defender, or lab dataset.

## What "tested" should mean

A rule can be marked tested only when:

1. The expected schema is confirmed.
2. The query runs without syntax errors.
3. At least one positive sample produces the expected match.
4. At least one benign sample does not alert or is documented as an acceptable false positive.
5. The detection write-up explains how an analyst should triage the result.
