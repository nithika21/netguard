# NetGuard Project Status

**Updated:** 2026-10-22  
**Overall:** Core app and repository structure are in place. The project still needs end-to-end verification and the Packet Explorer contrast issue reported during UI review is not confirmed fixed.

## Done or present in the project

- Split the Streamlit UI into `frontend/` and application services into `backend/`.
- Added project-level Streamlit light theme settings in `.streamlit/config.toml`.
- Implemented Dashboard, Anomaly Detection & Alerts, and Packet Explorer views.
- Added PCAP parsing, rule-based anomaly detection, alert/database handling, and CSV model prediction modules.
- Added sample PCAP, sample CSV files, trained model, and requirements file under the project.
- Added README run instructions and `.gitignore` rules for the local environment, Python caches, and local SQLite database.
- Created a GitHub remote and reconciled the unrelated initial commits. The last inspected local status showed `main` aligned with `origin/main` before these planning files were added.

## In progress / needs confirmation

- Packet Explorer still has reported low-contrast values and controls. Recent CSS and light-theme changes need to be checked in the running app; do not count this as fixed until source/destination endpoints, active filename, filters, and selectors are readable.
- The CSV prediction path was changed to use stored training medians instead of the serialized `SimpleImputer` internals. It needs an end-to-end run with the sample CSV and a compatible uploaded CSV.
- The PCAP, alert lifecycle, and database behavior are implemented but have not had a documented end-to-end verification pass in this work session.

## Remaining work

1. Fix and verify Packet Explorer contrast in the actual running app.
2. Walk through PCAP analysis, packet inspection, filters, alert creation, and alert status updates.
3. Walk through CSV analysis, prediction output, and invalid/incompatible CSV handling.
4. Add automated checks for core backend logic and an app smoke test.
5. Review upload/error handling and document data/model provenance and licensing.
6. Update README with complete setup and verification instructions, then prepare a release if needed.

## Known release considerations

- The app is currently a local Streamlit project; public hosting has not been configured.
- The SQLite file is local runtime state and should stay ignored by Git.
- Verify that included sample datasets, PCAP, and trained model can be redistributed before publishing a public release.
