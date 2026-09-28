# Password Strength & Predictable Mutation Analysis — Project Summary

## 1. Project Deliverables
- **Final Mathematical Report**: [`final_submission/Password_Strength_Predictable_Mutation_Final_Report.docx`](file:///c:/Users/nb200/Documents/Password_mutation/password_mutation_project/final_submission/Password_Strength_Predictable_Mutation_Final_Report.docx) (Updated with Section 8.3 Model Comparison and Objectives Matrix)
- **Final Presentation**: [`final_submission/Password_Strength_Predictable_Mutation_Presentation.pptx`](file:///c:/Users/nb200/Documents/Password_mutation/password_mutation_project/final_submission/Password_Strength_Predictable_Mutation_Presentation.pptx) (20 slides, includes baseline comparison and 3-password benchmark)
- **Core Python Library**: [`password_analyzer/`](file:///c:/Users/nb200/Documents/Password_mutation/password_mutation_project/password_analyzer/) (`core.py`, `baseline_comparator.py`, `dataset_pipeline.py`, `experiment_runner.py`, `cli.py`)
- **Interactive Web Application**: [`app.py`](file:///c:/Users/nb200/Documents/Password_mutation/password_mutation_project/app.py) (Streamlit dashboard with 6 specialized tabs)
- **Automated Research Suite**: [`experiments.py`](file:///c:/Users/nb200/Documents/Password_mutation/password_mutation_project/experiments.py)
- **Synthetic & Research Datasets**: [`data/`](file:///c:/Users/nb200/Documents/Password_mutation/password_mutation_project/data/) (`synthetic_password_dataset_phase3.csv`, calibration splits, and example research pipeline dataset)
- **Experimental Reports & Graphs**: [`results/`](file:///c:/Users/nb200/Documents/Password_mutation/password_mutation_project/results/) (`baseline_comparison.csv`, `BASELINE_COMPARISON_REPORT.md`, 8 publication figures)
- **Automated Pytest Suite**: [`tests/test_core.py`](file:///c:/Users/nb200/Documents/Password_mutation/password_mutation_project/tests/test_core.py)

---

## 2. Project Objectives Fulfillment Matrix

| Original Objective | Technical Implementation | Empirical Evidence / Artifact | Verification Status |
| :--- | :--- | :--- | :---: |
| **Measure conventional password strength** | Theoretical search-space ($S = N^L$) and Shannon entropy ($H = L \log_2 N$) model | [`password_analyzer/core.py`](file:///c:/Users/nb200/Documents/Password_mutation/password_mutation_project/password_analyzer/core.py), [`results/baseline_comparison.csv`](file:///c:/Users/nb200/Documents/Password_mutation/password_mutation_project/results/baseline_comparison.csv) | **COMPLETED** |
| **Detect dictionary and pattern risks** | Substring dictionary matcher against common educational base words | `find_dictionary_base()` in [`core.py`](file:///c:/Users/nb200/Documents/Password_mutation/password_mutation_project/password_analyzer/core.py) | **COMPLETED** |
| **Detect predictable mutations** | 4-channel detector for capitalization, leetspeak substitution, numeric suffixes, and symbol suffixes | `detect_mutations()` & `mutation_components()` in [`core.py`](file:///c:/Users/nb200/Documents/Password_mutation/password_mutation_project/password_analyzer/core.py) | **COMPLETED** |
| **Develop Mutation Vulnerability Score (MVS)** | Fixed weights and Laplace-smoothed empirical probability weighting ($\text{MVS}_{\text{emp}}$) | Equations (4.4 & 4.5), [`results/empirical_mutation_probabilities.csv`](file:///c:/Users/nb200/Documents/Password_mutation/password_mutation_project/results/empirical_mutation_probabilities.csv) | **COMPLETED** |
| **Combine factors into realistic assessment** | Password Security Index: $\text{PSI} = 100 \cdot E_{\text{norm}} \cdot (1 - \text{MVS}/100)$ | `calculate_psi()` in [`core.py`](file:///c:/Users/nb200/Documents/Password_mutation/password_mutation_project/password_analyzer/core.py), [`app.py`](file:///c:/Users/nb200/Documents/Password_mutation/password_mutation_project/app.py) | **COMPLETED** |
| **Compare against conventional & existing methods** | Benchmark against conventional entropy and Dropbox `zxcvbn` | Section 8.3 of DOCX, [`results/BASELINE_COMPARISON_REPORT.md`](file:///c:/Users/nb200/Documents/Password_mutation/password_mutation_project/results/BASELINE_COMPARISON_REPORT.md) | **COMPLETED** |
| **Parameter Sensitivity & Independent Validation** | Phase 4 weight sweep and Phase 5 held-out split calibration ($H_{\text{ref}} = 50, \tau = 69$) | Phase 4 & 5 reports, [`results/phase5_validation_metrics.csv`](file:///c:/Users/nb200/Documents/Password_mutation/password_mutation_project/results/phase5_validation_metrics.csv) | **COMPLETED** |

---

## 3. Core Equations

$$S = N^L$$

$$H = L \cdot \log_2(N)$$

$$\hat{p} = \frac{k + 1}{n + 2}$$

$$I = -\log_2(\hat{p})$$

$$\text{MVS}_{\text{emp}} = 100 \times \frac{\sum w_i \hat{p}_i x_i}{\sum w_i x_i}$$

$$E_{\text{norm}} = \min\left(\frac{H}{H_{\text{ref}}}, 1\right)$$

$$\text{PSI} = 100 \times E_{\text{norm}} \times \left(1 - \frac{\text{MVS}}{100}\right)$$

---

## 4. Benchmark Performance Comparison

On the controlled synthetic benchmark dataset ($n = 330$):

| Assessment Method | Accuracy | Precision | Recall | F1-Score | ROC-AUC | Average Precision |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Proposed PSI** ($H_{\text{ref}}=50, \tau=69$) | **0.9788** | **1.0000** | **0.9333** | **0.9655** | **1.0000** | **1.0000** |
| **Proposed MVS** ($> 0$) | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| **Dropbox zxcvbn** (score $\le 2$) | 0.9242 | 0.8077 | 1.0000 | 0.8936 | 0.9937 | 0.9780 |
| **Conventional Entropy** ($< \text{median}$) | 0.8000 | 0.6211 | 0.9524 | 0.7519 | 0.9365 | 0.8913 |

---

## 5. Explicit Limitations & Scientific Scope

1. **Experimental Academic Status**: MVS and PSI are experimental project metrics. They are not NIST, ISO, or industry standards.
2. **Synthetic Dataset Scope**: Validation was performed on controlled synthetic datasets constructed for hypothesis testing; performance does not guarantee real-world cracking outcomes.
3. **Dictionary & Rules**: The current dictionary consists of 24 educational root words and 4 mutation channels. Real adversaries exploit extensive wordlists, rule combinators, and contextual tokens.
4. **Hardware-Dependent Cracking Times**: True offline cracking times depend entirely on the target hashing algorithm (e.g. fast MD5/NTLM vs. memory-hard Argon2id) and attacker GPU capacity.
5. **Complementary Role**: Proposed MVS/PSI provides interpretable, auditable construction telemetry to complement holistic pattern estimators like `zxcvbn`.
