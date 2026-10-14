import json, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

DATA = "/home/apathak/myr/break-x862/data/fingerprints"
OUT = "/home/apathak/myr/break-x862/report/figures"
os.makedirs(OUT, exist_ok=True)

MACHINES_ORDERED = [
    ("z420", "z420\nSandy Bridge-EP\n2012"),
    ("imac", "imac\nHaswell\n2013"),
    ("fuzzarch", "fuzzarch\nKaby Lake-R\n2017"),
    ("d153-system", "d153-system\nCoffee Lake\n2019"),
    ("lily", "lily\nTiger Lake\n2020"),
    ("debian", "debian\nTiger Lake\n2020"),
]
YEARS = {"z420": 2012, "imac": 2013, "fuzzarch": 2017, "d153-system": 2019, "lily": 2020, "debian": 2020.3}

runs = {}
for name, _ in MACHINES_ORDERED:
    lines = open(f"{DATA}/{name}.jsonl").read().splitlines()[1:]
    recs = {}
    for l in lines:
        r = json.loads(l)
        recs[(r["label"], r["state"])] = r
    runs[name] = recs

# ---------- Figure 1: feature support matrix ----------
FEATURES = [
    ("AVX2 (vpaddd ymm)",          "feat_avx2_vpaddd_ymm"),
    ("BMI1 (andn)",                "feat_bmi1_andn"),
    ("BMI2 (pext)",                "feat_bmi2_pext"),
    ("FMA (vfmadd132ps)",          "feat_fma_vfmadd132ps"),
    ("RDRAND",                     "grp0fc7full_modrmf0"),
    ("RDSEED",                     "grp0fc7full_modrmf8"),
    ("AES-NI, scalar (aesenc)",    "map66_38_dc"),
    ("PCLMULQDQ, scalar",          "map66_3a_44"),
    ("AES-NI, vectorized (vaesenc)", "vex38_dc"),
    ("VPCLMULQDQ, vectorized",     "vex3a_44"),
    ("SHA-NI (sha256rnds2)",       "feat_shani_sha256rnds2"),
    ("GFNI",                       "feat_gfni_vgf2p8affineqb"),
    ("CLFLUSHOPT-class",           "grp0fae66_b8"),
    ("AVX-512F (vaddps zmm)",      "avx512_vaddps_zmm"),
    ("AVX-512 VNNI",               "feat_avx512vnni_vpdpbusd"),
    ("AVX-512 BITALG",             "feat_avx512bitalg_vpopcntb"),
    ("PKU (rdpkru)",               "grp0f01full_modrmee"),
    ("UMIP-restricted (sldt)",     "grp_0f00_reg0"),
    ("WAITPKG (umwait)",           "grp0faeF2_f0"),
]

def classify(name, label):
    zero = runs[name][(label, "zero_v1")]
    scratch = runs[name][(label, "scratch_v1")]
    # UMIP: special case -- "restricted" means GP in ring3 (that's the finding itself)
    if label == "grp_0f00_reg0":
        return 1 if zero["fault"] == "GP_OR_PF" else 0  # 1 = restricted(has UMIP), 0 = unrestricted
    # presence = executes under at least one state
    if zero["fault"] == "NONE" or scratch["fault"] == "NONE":
        return 2  # present
    if zero["fault"] == "UD" and scratch["fault"] == "UD":
        return 0  # absent
    return 1  # ambiguous/other

matrix = np.zeros((len(FEATURES), len(MACHINES_ORDERED)))
for i, (fname, label) in enumerate(FEATURES):
    for j, (name, _) in enumerate(MACHINES_ORDERED):
        matrix[i, j] = classify(name, label)

fig, ax = plt.subplots(figsize=(9, 8.5))
cmap = matplotlib.colors.ListedColormap(["#d6453d", "#e8a33d", "#3f8f5f"])
im = ax.imshow(matrix, cmap=cmap, vmin=0, vmax=2, aspect="auto")
ax.set_xticks(range(len(MACHINES_ORDERED)))
ax.set_xticklabels([lbl for _, lbl in MACHINES_ORDERED], fontsize=8)
ax.set_yticks(range(len(FEATURES)))
ax.set_yticklabels([f for f, _ in FEATURES], fontsize=9)
ax.set_xticks(np.arange(-.5, len(MACHINES_ORDERED), 1), minor=True)
ax.set_yticks(np.arange(-.5, len(FEATURES), 1), minor=True)
ax.grid(which="minor", color="white", linewidth=1.5)
ax.tick_params(which="minor", bottom=False, left=False)
for i in range(len(FEATURES)):
    for j in range(len(MACHINES_ORDERED)):
        v = matrix[i, j]
        label = {0: "UD", 1: "restricted" if FEATURES[i][1]=="grp_0f00_reg0" else "ambig.", 2: "exec" if FEATURES[i][1]!="grp_0f00_reg0" else "unrestr."}
        # simpler: custom text for umip row
        if FEATURES[i][1] == "grp_0f00_reg0":
            txt = "GP" if v == 1 else "ok"
        else:
            txt = {0: "UD", 1: "?", 2: "OK"}[v]
        ax.text(j, i, txt, ha="center", va="center", fontsize=7.5, color="white", fontweight="bold")
legend_patches = [
    mpatches.Patch(color="#3f8f5f", label="present / executes"),
    mpatches.Patch(color="#e8a33d", label="ambiguous (or: UMIP-restricted)"),
    mpatches.Patch(color="#d6453d", label="absent (#UD)"),
]
ax.legend(handles=legend_patches, loc="upper center", bbox_to_anchor=(0.5, -0.06), ncol=3, fontsize=8, frameon=False)
ax.set_title("Instruction/feature support across the fleet\n(derived entirely from black-box #UD-vs-executes behavior, no cpuid read)", fontsize=10)
plt.tight_layout()
plt.savefig(f"{OUT}/feature_matrix.pdf", dpi=200, bbox_inches="tight")
plt.savefig(f"{OUT}/feature_matrix.png", dpi=200, bbox_inches="tight")
print("Figure 1 done")

# ---------- Figure 2: cross-machine agreement across the three sweeps ----------
sweep_info = [
    ("Sweep 1\n823 candidates\n4 machines", 818, 823),
    ("Sweep 2\n2,689 candidates\n5 machines", 5294, 5378),
    ("Sweep 3\n4,996 candidates\n6 machines", 9992-824, 9992),
]
labels = [s[0] for s in sweep_info]
pct = [100*s[1]/s[2] for s in sweep_info]
fig, ax = plt.subplots(figsize=(6.5, 4))
bars = ax.bar(labels, pct, color=["#3f8f5f", "#3f8f5f", "#3f8f5f"], width=0.55)
for b, p in zip(bars, pct):
    ax.text(b.get_x()+b.get_width()/2, p+0.5, f"{p:.1f}%", ha="center", fontsize=10, fontweight="bold")
ax.set_ylim(0, 105)
ax.set_ylabel("Rows identical across every machine (%)")
ax.set_title("Cross-machine agreement rate as the corpus widens\n(each sweep deliberately targets more divergence-prone instruction groups)", fontsize=9.5)
ax.spines[["top","right"]].set_visible(False)
plt.tight_layout()
plt.savefig(f"{OUT}/agreement_rate.pdf", dpi=200, bbox_inches="tight")
plt.savefig(f"{OUT}/agreement_rate.png", dpi=200, bbox_inches="tight")
print("Figure 2 done")

# ---------- Figure 3: GP_OR_PF disambiguation on lily (sweep 2 numbers, reproduced in sweep 3) ----------
fig, ax = plt.subplots(figsize=(5.5, 4))
vals = [1000, 164]
labs = ["NULL-pointer artifact\n(flips under scratch_v1)", "genuine privilege fault\n(persists under both states)"]
colors = ["#e8a33d", "#3f8f5f"]
wedges, texts, autotexts = ax.pie(vals, labels=labs, autopct=lambda p: f"{p:.0f}%\n(n={int(round(p/100*1164))})",
                                    colors=colors, startangle=90, textprops={"fontsize":9})
ax.set_title("What the 1,164 \"GP_OR_PF\" results under zero_v1\nactually were (lily, sweep 2 corpus)", fontsize=10)
plt.tight_layout()
plt.savefig(f"{OUT}/gppf_breakdown.pdf", dpi=200, bbox_inches="tight")
plt.savefig(f"{OUT}/gppf_breakdown.png", dpi=200, bbox_inches="tight")
print("Figure 3 done")

# ---------- Figure 4: generational timeline ----------
timeline_features = [
    ("RDRAND", "grp0fc7full_modrmf0", 2012),
    ("RDSEED", "grp0fc7full_modrmf8", 2014),
    ("AVX2/BMI1/BMI2/FMA", "feat_avx2_vpaddd_ymm", 2013),
    ("CLFLUSHOPT-class", "grp0fae66_b8", 2015),
    ("AVX-512F", "avx512_vaddps_zmm", 2017),
    ("UMIP enforcement", "grp_0f00_reg0", 2018),
    ("AES-NI/PCLMULQDQ, vectorized", "vex38_dc", 2019),
    ("PKU", "grp0f01full_modrmee", 2019),
]
fig, ax = plt.subplots(figsize=(10, 5))
machine_x = {name: YEARS[name] for name, _ in MACHINES_ORDERED}
for idx, (fname, label, intro_year) in enumerate(timeline_features):
    y = idx
    for name, _ in MACHINES_ORDERED:
        if label == "grp_0f00_reg0":
            present = runs[name][(label, "zero_v1")]["fault"] == "GP_OR_PF"
        else:
            present = classify(name, label) == 2
        x = machine_x[name]
        marker = "o" if present else "x"
        color = "#3f8f5f" if present else "#d6453d"
        ax.scatter(x, y, marker=marker, s=90, color=color, zorder=3,
                   edgecolors="black" if present else None, linewidths=0.6)
ax.axvline(2013.5, color="gray", linestyle=":", linewidth=0.8)
ax.set_yticks(range(len(timeline_features)))
ax.set_yticklabels([f"{f} (doc. ~{y})" for f, _, y in timeline_features], fontsize=9)
ax.set_xticks([YEARS[n] for n, _ in MACHINES_ORDERED])
ax.set_xticklabels([f"{n}\n{int(YEARS[n])}" for n, _ in MACHINES_ORDERED], fontsize=8)
ax.set_xlabel("machine, ordered by CPU release year")
ax.set_title("Silicon feature timeline reconstructed purely from black-box fault behavior\n(circle = executes, cross = #UD; years in row labels are each feature's documented Intel introduction generation)", fontsize=9.5)
ax.set_ylim(-0.7, len(timeline_features)-0.3)
ax.invert_yaxis()
for spine in ["top", "right"]:
    ax.spines[spine].set_visible(False)
plt.tight_layout()
plt.savefig(f"{OUT}/timeline.pdf", dpi=200, bbox_inches="tight")
plt.savefig(f"{OUT}/timeline.png", dpi=200, bbox_inches="tight")
print("Figure 4 done")
