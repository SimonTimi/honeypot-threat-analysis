import numpy as np, pandas as pd, matplotlib.pyplot as plt

df = pd.read_pickle("cowrie_events.pkl")
OWN_IPS = set()                       # add your own home/uni IPs here
df = df[df.src_ip.notna() & ~df.src_ip.isin(OWN_IPS)]

# Fair comparison: only the period when ALL sensors were collecting
start = df.groupby("vm")["ts"].min().max()
end = df.groupby("vm")["ts"].max().min()
d = df[(df.ts >= start) & (df.ts <= end)]
print("Common window:", start, "->", end)

first = d.groupby(["src_ip", "vm"])["ts"].min().unstack()     # first contact per IP per VM
n_seen = first.notna().sum(axis=1)
print(n_seen.value_counts().sort_index())

gcols = [c for c in first.columns if c.startswith("google")]
if "azure_sensor" not in first.columns or not gcols:
    raise SystemExit(f"Need both Azure and Google data. Only found: {list(first.columns)}")

mask = first["azure_sensor"].notna() & first[gcols].notna().any(axis=1)
both = first[mask].copy()
if both.empty:
    raise SystemExit("No IPs appear on both providers in the common window.")

both["google_first"] = pd.to_datetime(both[gcols].min(axis=1), utc=True)
both["lag_min"] = (both["google_first"] - both["azure_sensor"]).dt.total_seconds() / 60
both["first_hit"] = np.select([both.lag_min > 0, both.lag_min < 0], ["Azure first", "Google first"], "Same time")

# IPs seen on every sensor, and on how many distinct days
days = d.groupby("src_ip")["ts"].apply(lambda x: x.dt.date.nunique())
print(days[n_seen[n_seen == n_seen.max()].index].sort_values(ascending=False).head(15))

fig, ax = plt.subplots(1, 3, figsize=(16, 4))
n_seen.value_counts().sort_index().plot.bar(ax=ax[0], title="IPs by number of sensors contacted")
bins = np.logspace(-2, np.log10(both.lag_min.abs().max() + 1), 40)
ax[1].hist(both.lag_min.abs().clip(lower=0.01), bins=bins)
ax[1].set_xscale("log"); ax[1].set_title("Gap between first contact per provider (min)")
both.first_hit.value_counts().plot.pie(ax=ax[2], autopct="%1.0f%%", ylabel="")
plt.tight_layout(); plt.savefig("fig_cross_sensor.png", dpi=200)
both.sort_values("lag_min").to_csv("cross_provider_ips.csv")