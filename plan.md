# NetGuard Project Plan

This plan tracks the work needed to take NetGuard from its current local app to a dependable, documented release. Items are ordered by dependency and impact.

## 1. Finish the Packet Explorer experience

- Resolve remaining low-contrast text in packet metadata, upload status, filters, and selectors.
- Check the page in both PCAP and CSV modes at normal and narrow window widths.
- Make empty, invalid, and large-file states clear to the user.
- **Done when:** labels and values are readable on every background and interactive state, and the main Packet Explorer actions work end to end.

## 2. Verify PCAP analysis end to end

- Load `data/sample_traffic.pcap` and upload a separate capture.
- Check packet parsing, traffic summary, packet filters, packet detail selection, and anomaly association.
- Check alert persistence and status changes in the SQLite database.
- **Done when:** both the supplied capture and a valid uploaded capture complete without errors and show consistent packet and alert details.

## 3. Verify CSV machine-learning analysis

- Load `data/sample_traffic_test.csv` and upload a compatible CSV.
- Check missing-column and invalid-value handling, predictions, confidence values, and optional ground-truth metrics.
- Confirm the saved model works in the supported Python and scikit-learn environment.
- **Done when:** supported CSV inputs complete without errors and incompatible inputs receive a useful explanation.

## 4. Add repeatable checks

- Add unit tests for PCAP feature extraction, anomaly rules, CSV preprocessing, and database operations.
- Add a Streamlit app smoke test for navigation and key page states where practical.
- **Done when:** the checks run from documented commands and cover the core analysis paths.

## 5. Review reliability and safe input handling

- Review upload limits, CSV/PCAP parsing errors, database writes, and user-provided filenames and values.
- Confirm large inputs fail safely and do not leave the app in a broken session state.
- **Done when:** expected bad inputs fail cleanly and do not crash or corrupt stored data.

## 6. Complete documentation and repository setup

- Document environment setup, launch commands, sample assets, model training, and test commands in `README.md`.
- Record dataset/model sources and any applicable licenses or attribution requirements.
- Confirm `.gitignore` excludes local environments, caches, and the local database while retaining intentional sample assets.
- **Done when:** a fresh checkout can be set up by following the README and repository assets have clear provenance.

## 7. Prepare a release

- Run the documented checks and perform one final PCAP and CSV walkthrough.
- Review GitHub contents and commit history; tag a release if desired.
- Choose a deployment target only if the project needs a publicly hosted website.
- **Done when:** the release state is reproducible and its known limitations are documented.
