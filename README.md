# Honeypot Threat Analysis (T-Pot)

*Year 4 · H4015 Network Security Analytics, TU Dublin. Author: Simon Timi*

A multi-cloud honeynet built with T-Pot: a hive and sensor on Google Cloud plus an Azure sensor. Python scripts parse the Cowrie logs and analyse attacker behaviour.

## Contents
- `Log Files Prepper.py`: extracts and filters T-Pot log archives
- `load_cowrie.py`: loads Cowrie JSON events into a pandas DataFrame (`cowrie_events.pkl`)
- `Cross Sensor Attacker Correlation.py`: finds attacker IPs seen across the Google and Azure sensors
- `ATTCK Analysis and Behavior.py`: clusters sessions with K-Means and maps behaviour to MITRE ATT&CK
- `Credential Intelligence.py`: analyses brute-forced usernames and passwords
- `fig_*.png`: output figures; `*.csv` / `*.xlsx`: derived data such as VirusTotal hash results
- `B00163297SimonTimiNetSec1.docx`: report

The raw honeypot logs (~1 GB) and the intermediate pickle are not included in the repo.

**Stack:** Python, pandas, scikit-learn, matplotlib, T-Pot, Cowrie
