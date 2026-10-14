import json, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

DATA = "/home/apathak/myr/break-x862/data/fingerprints"
OUT = "/home/apathak/myr/break-x862/report/figures"

MACHINES_ORDERED = [
    ("z420", "z420", "Sandy Bridge-EP", 2012),
    ("imac", "imac", "Haswell", 2013),
    ("fuzzarch", "fuzzarch", "Kaby Lake-R", 2017),
    ("d153-system", "d153-system", "Coffee Lake", 2019),
    ("lily", "lily", "Tiger Lake", 2020),
    ("debian", "debian", "Tiger Lake", 2020),
]

runs = {}
for name, *_ in MACHINES_ORDERED:
    lines = open(f"{DATA}/{name}.jsonl").read().splitlines()[1:]
    recs = {}
    for l in lines:
        r = json.loads(l)
        recs[(r["label"], r["state"])] = r
    runs[name] = recs

def present(name, label):
    zero = runs[name][(label, "zero_v1")]
    scratch = runs[name][(label, "scratch_v1")]
    return zero["fault"] == "NONE" or scratch["fault"] == "NONE"

timeline_features = [
    ("RDRAND", "grp0fc7full_modrmf0", 2012),
    ("RDSEED", "grp0fc7full_modrmf8", 2014),
    ("AVX2 / BMI1 / BMI2 / FMA", "feat_avx2_vpaddd_ymm", 2013),
    ("CLFLUSHOPT-class", "grp0fae66_b8", 2015),
    ("AVX-512F", "avx512_vaddps_zmm", 2017),
    ("UMIP enforcement", "grp_0f00_reg0", 2018),
    ("AES-NI / PCLMULQDQ, vectorized", "vex38_dc", 2019),
    ("PKU", "grp0f01full_modrmee", 2019),
]

x_pos = list(range(len(MACHINES_ORDERED)))
fig, ax = plt.subplots(figsize=(9.5, 5))
for idx, (fname, label, intro_year) in enumerate(timeline_features):
    y = idx
    for xi, (name, *_rest) in zip(x_pos, MACHINES_ORDERED):
        if label == "grp_0f00_reg0":
            is_present = runs[name][(label, "zero_v1")]["fault"] == "GP_OR_PF"
        else:
            is_present = present(name, label)
        marker = "o" if is_present else "x"
        color = "#3f8f5f" if is_present else "#d6453d"
        ax.scatter(xi, y, marker=marker, s=110, color=color, zorder=3,
                   edgecolors="black" if is_present else None, linewidths=0.7)

ax.axvline(1.5, color="gray", linestyle=":", linewidth=0.8)
ax.set_yticks(range(len(timeline_features)))
ax.set_yticklabels([f"{f}  (documented ~{y})" for f, _, y in timeline_features], fontsize=9.5)
ax.set_xticks(x_pos)
ax.set_xticklabels([f"{n}\n{ua}\n{yr}" for n, _, ua, yr in MACHINES_ORDERED], fontsize=8.5)
ax.set_xlim(-0.5, len(MACHINES_ORDERED) - 0.5)
ax.set_ylim(-0.7, len(timeline_features) - 0.3)
ax.invert_yaxis()
ax.set_title("Silicon feature timeline reconstructed purely from black-box fault behavior\n"
              "(circle = executes, cross = #UD; machines ordered left-to-right by CPU release year)",
              fontsize=10)
for spine in ["top", "right"]:
    ax.spines[spine].set_visible(False)
plt.tight_layout()
plt.savefig(f"{OUT}/timeline.pdf", dpi=200, bbox_inches="tight")
plt.savefig(f"{OUT}/timeline.png", dpi=200, bbox_inches="tight")
print("done")
