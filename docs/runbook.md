# Quick Runbook

1. Start Splunk Enterprise.
2. Upload the authorized CSV into the `main` index.
3. Set the time picker to **All time**.
4. Run `spl/00_field_discovery.spl`.
5. Verify CSV field names and correct the quoted references if necessary.
6. Run the remaining SPL files one by one.
7. Save actual evidence in `reports/investigation_findings.md`.
8. Review false positives and dataset privacy before publishing screenshots.

If a query returns no results, check index, time range, sourcetype, field names
and timestamp parsing before concluding that the behavior is absent.
