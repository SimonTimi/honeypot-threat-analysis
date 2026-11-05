import numpy as np, pandas as pd, matplotlib.pyplot as plt
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
from sklearn.preprocessing import StandardScaler

df = pd.read_pickle("cowrie_events.pkl")
df = df[df.src_ip.notna()]
key = ["vm", "session"]
ct = pd.crosstab([df.vm, df.session], df.eventid)
s = pd.DataFrame(index=ct.index)
for col, name in [("cowrie.login.failed", "fails"), ("cowrie.login.success", "successes"), #for loop allows for grouping of events by session and vm, based on cowrie logs
                  ("cowrie.command.input", "n_cmds"), ("cowrie.session.file_download", "downloads"),
                  ("cowrie.session.file_upload", "uploads"), ("cowrie.direct-tcpip.request", "tcpip")]:
    s[name] = ct[col] if col in ct else 0
g = df.groupby(key)
s["src_ip"] = g["src_ip"].first()
s["start"] = g["ts"].min()
s["duration"] = g["duration"].max().fillna(0)
cmds = (df[df.eventid == "cowrie.command.input"].groupby(key)["input"]
        .apply(lambda x: " ; ".join(x.astype(str))))
s["cmds"] = cmds.reindex(s.index).fillna("")

TECH = {
 "T1082 System Information Discovery": r"\buname\b|/proc/cpuinfo|lscpu|\bfree\b|nproc|/proc/meminfo|\bdf\b|lspci|dmesg",
 "T1033 System Owner/User Discovery": r"\bwhoami\b|\bid\b|\bw\b|\blast\b|\bwho\b",
 "T1016 Network Config Discovery": r"ifconfig|ip (a|addr|route)|/etc/resolv",
 "T1083 File/Directory Discovery": r"\bls\b|\bfind\b|\bpwd\b",
 "T1105 Ingress Tool Transfer": r"\b(wget|curl|tftp|ftpget)\b",
 "T1222.002 Permissions Modification": r"\bchmod\b|\bchattr\b",
 "T1098.004 SSH Authorized Keys": r"authorized_keys",
 "T1053.003 Cron": r"\bcrontab\b|/etc/cron",
 "T1496 Resource Hijacking": r"xmrig|minerd|stratum|monero|cpuminer",
 "T1070 Indicator Removal": r"history -c|unset HISTFILE|rm -rf",
 "T1098 Account Manipulation": r"\bpasswd\b|chpasswd|usermod",
}
for name, rx in TECH.items():
    s[name] = s.cmds.str.contains(rx, case=False, regex=True)
s["T1105 Ingress Tool Transfer"] |= (s.downloads > 0) | (s.uploads > 0)
s["T1090 Proxy"] = s.tcpip > 0
s["T1110 Brute Force"] = s.fails > 0
s["T1595 Active Scanning"] = (s.fails + s.successes + s.n_cmds) == 0

miner = s["T1496 Resource Hijacking"]
persist = s["T1098.004 SSH Authorized Keys"] | s["T1053.003 Cron"]
deliver = s["T1105 Ingress Tool Transfer"]
s["category"] = np.select(
    [miner, persist, deliver, s.tcpip > 0, s.n_cmds > 0, s.successes > 0, s.fails > 0],
    ["Cryptominer deployment", "Persistence attempt", "Malware / tool delivery",
     "Proxy / port-forward abuse", "Reconnaissance / other commands",
     "Login only (no commands)", "Brute force only"],
    default="Connection / scan only")

print(s.category.value_counts())
print(s.groupby("category")["duration"].median())

mix = pd.crosstab(s.index.get_level_values("vm"), s.category, normalize="index")
mix.plot.barh(stacked=True, figsize=(12, 4), title="Session types by sensor")
plt.tight_layout(); plt.savefig("fig_session_types.png", dpi=200)

tech_cols = [c for c in s.columns if c.startswith("T") and c[1].isdigit()]
s[tech_cols].groupby(level="vm").sum().T.plot.barh(figsize=(10, 6), title="ATT&CK techniques observed")
plt.tight_layout(); plt.savefig("fig_attack_techniques.png", dpi=200)

# Validation: unsupervised clustering vs the rule-based labels
feats = ["fails", "successes", "n_cmds", "downloads", "uploads", "tcpip", "duration"]
Xs = StandardScaler().fit_transform(np.log1p(s[feats].astype(float)))
samp = np.random.default_rng(1).choice(len(Xs), min(20000, len(Xs)), replace=False)
k = max(range(3, 9), key=lambda k: silhouette_score(
    Xs[samp], KMeans(k, n_init=5, random_state=1).fit_predict(Xs[samp])))
s["cluster"] = KMeans(k, n_init=10, random_state=1).fit_predict(Xs)
print("k =", k); print(pd.crosstab(s.cluster, s.category)); print(s.groupby("cluster")[feats].median())

# Evidence for attribution
df[df.eventid == "cowrie.session.file_download"][["vm", "src_ip", "url", "shasum"]] \
  .drop_duplicates("shasum").to_csv("hashes_for_virustotal.csv", index=False)
print(df[df.eventid == "cowrie.command.input"].input.value_counts().head(20))
s.drop(columns="cmds").to_csv("sessions_classified.csv")