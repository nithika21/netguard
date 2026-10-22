<<<<<<< HEAD
# NetGuard

## Project structure

- `frontend/` contains the Streamlit user interface.
- `backend/` contains configuration, packet analysis, anomaly detection, model inference, database access, and utility scripts.
- `data/` contains the SQLite database, sample datasets, trained model, and optional sample PCAP.
- `requirements.txt` lists the Python dependencies.

## Run the application

From the project root, activate the project's Python environment and run:

```bash
streamlit run frontend/app.py
```

## Backend utilities

Run these from the project root:

```bash
python -m backend.generate_sample_pcap
python -m backend.train_model
```
=======
# netguard
NetGuard is a Streamlit app for analyzing network traffic from PCAP files and CSV flow datasets. It combines packet analysis and rule-based anomaly detection with a Random Forest classifier to help inspect suspicious traffic and alerts.
>>>>>>> 3b2ba5349483822c9618679c207a4ae82a80db8b
