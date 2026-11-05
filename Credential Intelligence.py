import numpy as np, pandas as pd, matplotlib.pyplot as plt
from pathlib import Path

df = pd.read_pickle("cowrie_events.pkl")
c = df[df.eventid.isin(["cowrie.login.failed", "cowrie.login.success"])].copy()
c["username"] = c.username.fillna(""); c["password"] = c.password.fillna("")
c["pair"] = c.username + ":" + c.password

print(c.groupby("vm").agg(attempts=("pair", "size"), usernames=("username", "nunique"),
      passwords=("password", "nunique"), pairs=("pair", "nunique"), ips=("src_ip", "nunique")))

for prov, g in c.groupby("provider"):
    print("\n==", prov)
    print(g.username.value_counts().head(10)); print(g.password.value_counts().head(10))
    print(g.pair.value_counts().head(10))

# Concentration: how few passwords cover most attempts?
plt.figure(figsize=(7, 4))
for prov, g in c.groupby("provider"):
    share = g.password.value_counts(normalize=True).cumsum().values
    plt.plot(np.arange(1, len(share) + 1), share, label=prov)
plt.xscale("log"); plt.xlabel("Top N passwords"); plt.ylabel("Share of attempts"); plt.legend()
plt.tight_layout(); plt.savefig("fig_password_concentration.png", dpi=200)

# Wordlist overlap (download a common-passwords list, e.g. from SecLists, and set the path)
WL = Path(r"C:\wordlists\10k-most-common.txt")
if WL.exists():
    common = set(WL.read_text(errors="ignore").splitlines())
    c["in_wordlist"] = c.password.isin(common)
    print("Share of attempts in wordlist:\n", c.groupby("provider").in_wordlist.mean())
    print("Share of unique passwords in wordlist:\n",
          c.drop_duplicates(["provider", "password"]).groupby("provider").in_wordlist.mean())

# Subset of the Mirai dictionary; extend it from the published analysis
MIRAI = {("root","xc3511"),("root","vizxv"),("root","admin"),("admin","admin"),("root","888888"),
         ("root","xmhdipc"),("root","default"),("root","juantech"),("root","123456"),("root","54321"),
         ("support","support"),("root",""),("admin","password"),("root","root"),("root","12345"),
         ("user","user"),("admin",""),("root","pass"),("admin","admin1234"),("root","1111"),
         ("admin","smcadmin"),("admin","1111"),("root","666666"),("root","password"),
         ("root","1234"),("guest","guest"),("ubnt","ubnt")}
c["mirai_dict"] = [(u, p) in MIRAI for u, p in zip(c.username, c.password)]
c["empty_pw"] = c.password.eq("")
c["pw_eq_user"] = c.password.eq(c.username)
c["digits_only"] = c.password.str.fullmatch(r"\d+")
print(c.groupby("provider")[["mirai_dict", "empty_pw", "pw_eq_user", "digits_only"]].mean().round(3))
print(c.groupby("provider").password.apply(lambda x: x.str.len().describe()))

# Attacker style: one guess vs short list vs real dictionary
per_ip = c.groupby(["provider", "src_ip"]).agg(attempts=("pair", "size"), distinct=("pair", "nunique"))
per_ip["style"] = pd.cut(per_ip.distinct, [0, 1, 5, 50, np.inf],
                         labels=["single guess", "short list (2-5)", "dictionary (6-50)", "large (50+)"])
print(per_ip.groupby(["provider", "style"], observed=False).size().unstack())

# Do the providers see the same credential lists?
rank = {p: g.password.value_counts().head(200).index.tolist() for p, g in c.groupby("provider")}
ga, aa = set(rank["google"]), set(rank["azure"])
print("Jaccard top-200 passwords:", round(len(ga & aa) / len(ga | aa), 3))
print("Google-only:", [x for x in rank["google"] if x not in aa][:15])
print("Azure-only:", [x for x in rank["azure"] if x not in ga][:15])

fig, ax = plt.subplots(1, 2, figsize=(12, 4))
for a_, (prov, g) in zip(ax, c.groupby("provider")):
    g.password.replace("", "(empty)").value_counts().head(15).sort_values().plot.barh(ax=a_, title=f"Top passwords: {prov}")
plt.tight_layout(); plt.savefig("fig_top_passwords.png", dpi=200)