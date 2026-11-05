import json
from pathlib import Path
import pandas as pd

SRC = Path(r"E:\tpot upload")
KEEP = {"cowrie.session.connect", "cowrie.login.failed", "cowrie.login.success",
        "cowrie.command.input", "cowrie.session.file_download", "cowrie.session.file_upload",
        "cowrie.session.closed", "cowrie.direct-tcpip.request"}
rows = []
for p in sorted(SRC.glob("cowrie__*.json")):
    vm = p.name.split("__")[1]                      # google_hive / google_sensor / azure_sensor
    with open(p, encoding="utf-8", errors="ignore") as f:
        for line in f:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get("eventid") not in KEEP:
                continue
            rows.append({"vm": vm, "ts": e.get("timestamp"), "eventid": e["eventid"],
                         "src_ip": e.get("src_ip"), "session": e.get("session"),
                         "username": e.get("username"), "password": e.get("password"),
                         "input": e.get("input"), "url": e.get("url"),
                         "shasum": e.get("shasum"), "duration": e.get("duration"),
                         "protocol": e.get("protocol")})

df = pd.DataFrame(rows)
df["ts"] = pd.to_datetime(df["ts"], utc=True, errors="coerce")
df["duration"] = pd.to_numeric(df["duration"], errors="coerce")
df["provider"] = df["vm"].str.split("_").str[0]     # google / azure
df.to_pickle("cowrie_events.pkl")
print(df.groupby(["vm", "eventid"]).size().unstack(fill_value=0).T)
print(df.groupby("vm")["ts"].agg(["min", "max"]))