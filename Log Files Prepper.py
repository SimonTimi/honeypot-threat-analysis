import gzip, re, tarfile
from pathlib import Path, PurePosixPath

SRC = {  # set what you have; add the Google archives later
    "azure_sensor": Path(r"C:\Users\simon\OneDrive - Technological University Dublin\YEAR 4\SEMESTER 1\H4015 Network Security Analytics\Honey Pot Project\HoneyPot Logs\Azure Logs\.json log files"),
     "google_sensor": Path(r"C:\Users\simon\OneDrive - Technological University Dublin\YEAR 4\SEMESTER 1\H4015 Network Security Analytics\Honey Pot Project\HoneyPot Logs\GOOGLE SENSOTtpot-logs-full.tar.gz"),
     "google_hive":   Path(r"E:\tpot-logs-full.tar.gz"),
}
OUT = Path(r"E:\tpot upload"); OUT.mkdir(exist_ok=True)
MAX = 400 * 1024 * 1024
ALERT = re.compile(r'"event_type"\s*:\s*"alert"')

def honeypot_of(name):
    parts = [x.lower() for x in PurePosixPath(name.replace("\\", "/")).parts]
    idx = [i for i, x in enumerate(parts[:-1]) if x == "log"]
    return parts[idx[-1] - 1] if idx and idx[-1] > 0 else parts[-1].split(".")[0]

def entries(src):
    if src.is_dir():
        for p in sorted(src.rglob("*")):
            if p.is_file():
                yield str(p), (lambda p=p: open(p, "rb"))
    else:
        tar = tarfile.open(src, "r:*")
        for m in tar:
            if m.isfile():
                yield m.name, (lambda m=m: tar.extractfile(m))

for host, src in SRC.items():
    state, matched = {}, 0
    for name, opener in entries(src):
        low = name.lower().replace("\\", "/")
        if "json" not in low.rsplit("/", 1)[-1] or "/log/" not in low:  # file name, not folder (".json log files")
            continue
        f = opener()
        if low.endswith(".gz"):
            f = gzip.GzipFile(fileobj=f)
        hp = honeypot_of(name); matched += 1
        for raw in f:
            line = raw.decode("utf-8", "ignore").strip()
            if not line.startswith("{"):
                continue
            if hp == "suricata" and not ALERT.search(line):
                continue
            s = state.get(hp)
            if s is None or s[2] > MAX:
                n = 1
                if s:
                    s[1].close(); n = s[0] + 1
                s = state[hp] = [n, open(OUT / f"{hp}__{host}__{n:02d}.json", "w", encoding="utf-8"), 0]
            s[1].write(line + "\n"); s[2] += len(line) + 1
    for s in state.values():
        s[1].close()
    print(host, "-", matched, "json files read")

for f in sorted(OUT.glob("*.json")):
    print(f.name, round(f.stat().st_size / 1e6, 1), "MB")