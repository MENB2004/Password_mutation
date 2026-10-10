# Phase 5 — Independent Calibration and Held-out Validation

A new synthetic dataset was generated with a different random seed and split into a
calibration subset and a held-out evaluation subset.

## Calibration
Candidate H_ref values: [50, 60, 70, 80, 90, 100, 120]

Selected using calibration data only:

    H_ref = 50

Selected PSI classification threshold using calibration data only:

    threshold = 69.0

## Held-out results (Original Split)

*Note on Confusion Matrix:* Positive class is defined as `target = 1` (Predictable Mutation / Vulnerable Family), and negative class as `target = 0` (Synthetic Random Control).

| selected_H_ref | calibration_threshold | calibration_acc | heldout_acc | heldout_auc_PSI | heldout_ap_PSI | heldout_auc_conv | heldout_ap_conv | TN | FP | FN | TP |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 50 | 69.0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.9851 | 0.9913 | 118 | 0 | 0 | 62 |

## Held-out group summary

| target | n | mean_entropy | mean_conventional | mean_mvs | mean_psi |
|---|---|---|---|---|---|
| 0 (Random Control) | 118 | 82.74 bits | 85.38 | 0.00 | 100.00 |
| 1 (Predictable Mutation) | 62 | 44.94 bits | 52.57 | 33.95 | 56.18 |

---

## Rigorous Root-Contamination Audit

A deep audit of the Phase 5 datasets (`phase5_calibration_split.csv` and `phase5_heldout_split.csv`) revealed:
1. **Root Overlap:** 14 out of 14 dictionary roots in the held-out evaluation set (`['admin', 'college', 'computer', 'dragon', 'football', 'hello', 'master', 'secret', 'security', 'spring', 'student', 'summer', 'welcome', 'winter']`) were also present in the calibration split.
2. **Duplicate Records:** 19 exact duplicate passwords existed between the calibration and held-out subsets due to non-disjoint random sampling.
3. **Template Circularity:** Evaluated models tested templates constructed from the same mutation rules known to the feature extractors.

---

## Family-Disjoint Evaluation Split (New Protocol)

To address root contamination, a strictly family-disjoint split protocol was established (`data/phase5_family_disjoint_calibration_split.csv` and `data/phase5_family_disjoint_eval_split.csv`):
- **Calibration Roots ($N=60$ positive):** `['football', 'hello', 'secret', 'spring', 'student', 'summer']`
- **Evaluation Roots ($N=60$ positive):** `['admin', 'college', 'computer', 'dragon', 'master', 'password', 'security', 'welcome', 'winter']`
- **Negative Controls:** 240 unique random strings partitioned 120 / 120 (zero overlap).
- **Exact Overlap:** 0 duplicate passwords, 0 shared dictionary roots between calibration and evaluation.

### Benchmark Performance on Family-Disjoint Evaluation Set ($N=180$)

| Model | Accuracy | Precision | Recall | F1-Score | ROC-AUC | PR-AUC | TN | FP | FN | TP |
|---|---|---|---|---|---|---|---|---|---|---|
| **Calibrated PSI ($\tau=69$, Emp MVS)** | 0.9389 | 1.0000 | 0.8167 | 0.8991 | 1.0000 | 1.0000 | 120 | 0 | 11 | 49 |
| **Fixed MVS ($\ge 20.0$)** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 120 | 0 | 0 | 60 |
| **Empirical MVS ($\ge 20.0$)** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 120 | 0 | 0 | 60 |
| **Dropbox zxcvbn ($\le 2$)** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 120 | 0 | 0 | 60 |
| **Conventional Entropy ($< \text{median}$)** | 0.8556 | 0.6977 | 1.0000 | 0.8219 | 0.9900 | 0.9806 | 94 | 26 | 0 | 60 |

*Analysis of Calibrated PSI False Negatives:* The 11 false negatives in Calibrated PSI occur on passwords such as `security2026`, `welcome2026`, and `computer2026`, where only base + numeric suffix are active. Under empirical Laplace smoothing, their empirical MVS is $30.85$, yielding $\text{PSI}_{\text{cal}} = 69.15$, which sits $0.15$ points above the rigid $\tau = 69.0$ decision boundary. Under Fixed-Weights MVS ($MVS = 55.0$), PSI is $45.0 \ll 69.0$, resulting in $100\%$ Recall.

---

## Interpretation & Scientific Defensibility

1. The models demonstrate robust separation between dictionary mutations and random controls even across unseen root vocabularies.
2. The metrics describe performance on rule-synthesized mutations and do not directly translate to real-world password cracking resistance or breached credential populations.
3. Industry tools (Dropbox zxcvbn) perform exceptionally well on synthetic mutations due to built-in spatial pattern and dictionary matching.

## Limitations

- Validation data remains synthetic.
- Labels are deterministic by construction.
- Real human password mutations involve contextual patterns (names, dates, slang) beyond synthetic permutations.
