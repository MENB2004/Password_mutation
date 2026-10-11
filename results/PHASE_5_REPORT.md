# Phase 5 — Rigorous Independent Calibration & Family-Disjoint Evaluation Report

## 1. Executive Summary & Protocol Audit

This report documents the rigorous evaluation protocol and held-out validation benchmark designed to assess the generalization of the proposed Password Security Index (PSI) and Mutation Vulnerability Score (MVS) models on previously unseen password roots.

### Leakage Audit & Dataset Integrity
- **Calibration Split:** `data/phase5_family_disjoint_calibration_split.csv` ($N = 180$, 60 positive mutations, 120 synthetic random controls)
- **Evaluation Split:** `data/phase5_family_disjoint_eval_split.csv` ($N = 180$, 60 positive mutations, 120 synthetic random controls)
- **Password Overlap:** **0** duplicate passwords between calibration and evaluation sets.
- **Root-Family Overlap:** **0** shared dictionary roots between calibration and evaluation sets.
  - Calibration Roots: `['football', 'hello', 'secret', 'spring', 'student', 'summer']`
  - Evaluation Roots: `['admin', 'college', 'computer', 'dragon', 'master', 'password', 'security', 'welcome', 'winter']`
- **Negative Controls Overlap:** **0** duplicate random controls (240 disjoint random strings generated under independent entropy seeds).
- **Leakage Prevention:** Reference entropy ($H_{\text{ref}} = 50.0$) and classification threshold ($\tau = 69.0$) were frozen on calibration data prior to evaluating held-out data.

---

## 2. Benchmark Performance on Held-Out Family-Disjoint Evaluation Set ($N = 180$)

All models evaluated strictly with parameters frozen from the calibration phase:

| Model / Estimator | Decision Threshold | Accuracy | Precision | Recall | F1-Score | ROC-AUC | PR-AUC | Confusion Matrix (TN, FP, FN, TP) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Proposed PSI (Fixed MVS)** | $\text{PSI} < 69.0$ | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | (120, 0, 0, 60) |
| **Proposed PSI (Empirical MVS)** | $\text{PSI} < 69.0$ | 0.9389 | 1.0000 | 0.8167 | 0.8991 | 1.0000 | 1.0000 | (120, 0, 11, 49) |
| **Proposed Fixed MVS** | $\text{MVS} \ge 20.0$ | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | (120, 0, 0, 60) |
| **Proposed Empirical MVS** | $\text{MVS}_{\text{emp}} \ge 20.0$ | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | (120, 0, 0, 60) |
| **Dropbox zxcvbn** | $\text{score} \le 2$ | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | (120, 0, 0, 60) |
| **Conventional Entropy** | $H < \text{median}$ | 0.8556 | 0.6977 | 1.0000 | 0.8219 | 0.9900 | 0.9806 | (94, 26, 0, 60) |

---

## 3. Threshold Sensitivity Investigation (Evaluated on Calibration Data Only)

We evaluated threshold sensitivity across candidate decision boundaries $\tau \in [50, 90]$ strictly using the independent calibration subset ($N = 180$):

| Threshold $\tau$ | Fixed MVS Acc | Fixed MVS Rec | Fixed MVS F1 | Fixed MVS FN | Emp MVS Acc | Emp MVS Rec | Emp MVS F1 | Emp MVS FN |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| $\tau = 50.0$ | 0.9778 | 0.9333 | 0.9655 | 4 | 0.7389 | 0.2167 | 0.3562 | 47 |
| $\tau = 55.0$ | 0.9944 | 0.9833 | 0.9916 | 1 | 0.7778 | 0.3333 | 0.5000 | 40 |
| $\tau = 60.0$ | 1.0000 | 1.0000 | 1.0000 | 0 | 0.8500 | 0.5500 | 0.7097 | 27 |
| $\tau = 65.0$ | 1.0000 | 1.0000 | 1.0000 | 0 | 0.9000 | 0.7000 | 0.8235 | 18 |
| $\tau = 69.0$ | 1.0000 | 1.0000 | 1.0000 | 0 | 0.9556 | 0.8667 | 0.9286 | 8 |
| $\tau = 70.0$ | 1.0000 | 1.0000 | 1.0000 | 0 | 1.0000 | 1.0000 | 1.0000 | 0 |
| $\tau = 75.0$ | 1.0000 | 1.0000 | 1.0000 | 0 | 1.0000 | 1.0000 | 1.0000 | 0 |
| $\tau = 80.0$ | 1.0000 | 1.0000 | 1.0000 | 0 | 1.0000 | 1.0000 | 1.0000 | 0 |
| $\tau = 85.0$ | 1.0000 | 1.0000 | 1.0000 | 0 | 1.0000 | 1.0000 | 1.0000 | 0 |
| $\tau = 90.0$ | 1.0000 | 1.0000 | 1.0000 | 0 | 1.0000 | 1.0000 | 1.0000 | 0 |

### Root-Cause Analysis of False Negatives at $\tau = 69.0$

Under Empirical Laplace Smoothing:
- Passwords containing only dictionary base + numeric suffix (e.g., `welcome2026`, `security2026`, `computer2026`) activate:
  - $w_{\text{base}} = 0.35, \hat{p}_{\text{base}} = 0.3193$
  - $w_{\text{num}} = 0.20, \hat{p}_{\text{num}} = 0.2897$
- Their empirical MVS is:
  $$\text{MVS}_{\text{emp}} = 100 \times \frac{0.35(0.3193) + 0.20(0.2897)}{0.35 + 0.20} = 30.8529$$
- With $H > 50.0$ bits ($E_{\text{norm}} = 1.0$), their empirical PSI is:
  $$\text{PSI}_{\text{emp}} = 100 \times (1 - 0.308529) = 69.1471$$
- Because the rigid threshold rule classifies $\text{PSI} < 69.0$ as vulnerable, $69.1471 \ge 69.0$ results in **8 false negatives in calibration** and **11 false negatives in evaluation**.
- In contrast, under Fixed-Weights MVS:
  $$\text{MVS}_{\text{fixed}} = 35 + 20 = 55.0 \implies \text{PSI}_{\text{fixed}} = 45.0 \ll 69.0$$
  which achieves **0 false negatives (100% recall)**.
- If calibrated threshold is selected on calibration data to maximize F1, any $\tau \in [70.0, 85.0]$ achieves 100% accuracy and 0 false negatives on both calibration and evaluation sets.
- In accordance with scientific integrity guidelines, we preserve $\tau = 69.0$ as the project baseline specification and report these limitations transparently rather than retroactively tuning the threshold.

---

## 4. Scientific Defensibility and Real-World Limitations

1. **Theoretical vs. Real-World Entropy:** The character-pool Shannon entropy formula ($H = L \log_2 N$) assumes independent, uniform character choices. It serves as an upper bound on search space, not a measure of human password strength.
2. **Synthetic Template Circularity:** Because synthetic datasets are generated using predefined mutation templates, ML and heuristic classifiers evaluated on them exhibit artificially elevated accuracy (ROC-AUC $\approx 1.0$).
3. **No Crack-Time Guarantees:** High PSI or low MVS scores do not guarantee resistance to targeted dictionary attacks, credential stuffing, or tailored probabilistic cracking tools (e.g., Hashcat with custom rule masks, PCFG).
4. **Tool Role:** Proposed PSI is designed as an educational and heuristic feedback metric, complementing established spatial estimators such as Dropbox `zxcvbn`.
