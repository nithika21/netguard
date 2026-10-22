# NetGuard Project Status

**Updated:** 2026-10-22  
**Overall:** Core app and repository structure are in place. The project still needs end-to-end verification and the Packet Explorer contrast issue reported during UI review is not confirmed fixed.

## Subtask status

| ID | Area | Subtask | Status | Notes |
|---|---|---|---|---|
| 0.1 | Structure | Separate UI and backend modules | Done | `frontend/` and `backend/` are in place. |
| 0.2 | UI | Add a light Streamlit theme and contrast styling | In progress | Packet Explorer endpoint/filename chips are still reported unreadable; verify in the running app. |
| 0.3 | Core app | Implement dashboard, alerts, and explorer pages | Implemented; verify | Pages and core code exist; no end-to-end pass recorded. |
| 0.4 | Assets | Include sample PCAP/CSV data and trained model | Done | Assets are present under `data/`. Check redistribution terms before public release. |
| 1.1 | Packet Explorer | Fix contrast for values, names, filters, and interactive states | In progress | Most recent report says endpoint fields remain unreadable. |
| 1.2 | Packet Explorer | Inspect PCAP and CSV modes at desktop and narrow widths | Not started | Needs visual walkthrough. |
| 1.3 | Packet Explorer | Check empty, invalid, and oversized-file states | Not started | Verify user-facing messages and recovery. |
| 2.1 | PCAP | Analyze the supplied sample and another valid capture | Not verified | Parser and sample exist; complete a manual walkthrough. |
| 2.2 | PCAP | Check summary, filters, and packet detail selection | Not verified | Confirm displayed values match the selected packet. |
| 2.3 | Alerts | Check rule association, persistence, and status updates | Not verified | Database and alert code exist; verify lifecycle. |
| 3.1 | CSV/ML | Run the supplied CSV and a compatible upload | Not verified | Median-based preprocessing fix needs an end-to-end run. |
| 3.2 | CSV/ML | Check prediction, confidence, missing values, and metrics | Not verified | Include an incompatible CSV case. |
| 3.3 | CSV/ML | Confirm saved model compatibility with documented dependencies | Not verified | Model is present; environment compatibility needs confirmation. |
| 4.1 | Quality | Add backend tests for parsing, rules, ML, and database | Not started | No automated test suite currently tracked. |
| 4.2 | Quality | Add a Streamlit smoke test | Not started | Consider navigation and core page states. |
| 5.1 | Reliability | Review upload limits, parser errors, and bad input handling | Not started | Check PCAP and CSV failure recovery. |
| 5.2 | Reliability | Review database writes and uploaded filenames/values | Not started | Confirm unsafe or malformed input is handled safely. |
| 6.1 | Docs | Document setup, launch, training, and checks in README | Partial | Launch and utility commands are documented; setup and checks need detail. |
| 6.2 | Docs | Record data/model sources and license requirements | Not started | Needed before a public release. |
| 6.3 | Git | Keep local environment/cache/database ignored | Done | `.gitignore` contains these rules. |
| 7.1 | Release | Run checks and complete final PCAP/CSV walkthrough | Not started | Depends on verification and tests above. |
| 7.2 | Release | Review GitHub contents and prepare a release | Not started | Git remote is configured; release review remains. |
| 7.3 | Hosting | Decide whether to deploy publicly | Optional | No deployment target has been selected. |

## Summary

- **Done:** project structure, app pages/core modules, sample assets, basic README, Streamlit theme configuration, and Git ignore rules.
- **In progress:** Packet Explorer contrast; the latest user screenshot still shows unreadable packet endpoint values.
- **Not yet verified:** end-to-end PCAP and CSV workflows, alert lifecycle, model/environment compatibility, and safe error recovery.
- **Not started:** automated test coverage, provenance/license documentation, release checks, and optional deployment.

## Known release considerations

- The app is currently a local Streamlit project; public hosting has not been configured.
- The SQLite file is local runtime state and should stay ignored by Git.
- Verify that included sample datasets, PCAP, and trained model can be redistributed before publishing a public release.
