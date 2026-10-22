# NetGuard Project Plan

This plan tracks the work needed to take NetGuard from its current local app to a dependable, documented release. Items are ordered by dependency and impact.

## 1. Finish the Packet Explorer experience

1.1 Fix contrast for packet values, filenames, filters, selectors, and their hover/focus states.  
1.2 Inspect PCAP and CSV modes at desktop and narrow window widths.  
1.3 Check empty, invalid, and oversized-file messages.  
**Done when:** all text is readable and the key controls work in both modes.

## 2. Verify PCAP analysis

2.1 Load the supplied `data/sample_traffic.pcap`.  
2.2 Upload a second valid capture.  
2.3 Check parsing, traffic summary, filters, and packet detail selection.  
2.4 Check anomaly association, alert persistence, and alert status changes.  
**Done when:** both captures produce consistent packet and alert details without errors.

## 3. Verify CSV machine-learning analysis

3.1 Load `data/sample_traffic_test.csv`.  
3.2 Upload a compatible CSV and inspect predictions and confidence values.  
3.3 Check missing columns, invalid values, and ground-truth metrics.  
3.4 Confirm the model loads in the documented Python/scikit-learn environment.  
**Done when:** supported data completes without errors and unsupported data gets a useful explanation.

## 4. Add repeatable checks

4.1 Add tests for packet parsing and anomaly rules.  
4.2 Add tests for CSV preprocessing and model inference.  
4.3 Add tests for database operations.  
4.4 Add a Streamlit smoke test for navigation and core page states where practical.  
**Done when:** checks run from documented commands and cover the core analysis paths.

## 5. Review reliability and safe input handling

5.1 Review upload size limits and PCAP/CSV parser errors.  
5.2 Review database writes and uploaded filename/value handling.  
5.3 Confirm invalid and large inputs fail safely without breaking session state.  
**Done when:** expected bad inputs fail cleanly without crashes or corrupted stored data.

## 6. Complete documentation and repository setup

6.1 Document environment setup, launch, sample assets, model training, and checks in `README.md`.  
6.2 Record dataset/model sources and applicable license or attribution requirements.  
6.3 Check `.gitignore` excludes local environments, caches, and the local database while retaining intended sample assets.  
**Done when:** a fresh checkout can be set up from the README and asset provenance is clear.

## 7. Prepare a release

7.1 Run documented checks and do a final PCAP/CSV walkthrough.  
7.2 Review GitHub contents and commit history; tag a release if desired.  
7.3 Choose a deployment target only if public hosting is needed.  
**Done when:** the release is reproducible and its known limitations are documented.
