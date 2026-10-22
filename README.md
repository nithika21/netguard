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
