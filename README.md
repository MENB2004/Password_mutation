# Password Strength & Predictable Mutation Analysis (Group 03)

A scientific Python research and analysis system that combines conventional Shannon entropy and search-space modeling with predictable mutation detection, empirical probability calibration, and comparisons against established industry password-strength estimators (Dropbox `zxcvbn`).

---

## Table of Contents
1. [Project Overview & Key Contributions](#project-overview--key-contributions)
2. [Original Objectives & Fulfillment Status](#original-objectives--fulfillment-status)
3. [Mathematical Framework](#mathematical-framework)
4. [Baseline Comparison Model (Dropbox zxcvbn)](#baseline-comparison-model-dropbox-zxcvbn)
5. [Canonical Benchmark Passwords](#canonical-benchmark-passwords)
6. [Real / Public Research Dataset Pipeline](#real--public-research-dataset-pipeline)
7. [Installation & Requirements](#installation--requirements)
8. [Usage Instructions](#usage-instructions)
   - [Interactive Streamlit Web Application](#1-interactive-streamlit-web-application)
   - [Command Line Interface (CLI)](#2-command-line-interface-cli)
   - [Automated Experiments & Baseline Benchmark](#3-automated-experiments--baseline-benchmark)
   - [Running Pytest Unit Tests](#4-running-pytest-unit-tests)
9. [Project Directory Structure](#project-directory-structure)
10. [Formal Academic Limitations & Ethical Disclaimers](#formal-academic-limitations--ethical-disclaimers)

---

## Project Overview & Key Contributions

Conventional password metrics rely heavily on **length** ($L$) and **character pool diversity** ($N$), evaluating theoretical entropy as $H = L \cdot \log_2(N)$. However, human password generation is notoriously non-random: users almost invariably start from a semantic root word (dictionary word, name, or concept) and apply predictable transformations (capitalizing the initial letter, substituting leetspeak symbols like `@` for `a` or `1` for `i`, and appending numeric years or exclamation marks). 

Conventional entropy assessments systematically **overestimate** the security of such passwords (giving them 70–85+ bits of theoretical entropy). 

This project introduces:
- **Mutation Vulnerability Score (MVS):** A structured metric quantifying five predictable construction vectors.
- **Empirical Probability Model:** Laplace-smoothed empirical frequencies ($\hat{p} = \frac{k+1}{n+2}$) and information surprisal ($I = -\log_2(\hat{p})$).
- **Password Security Index (PSI):** A penalized security metric balancing entropy with predictable mutation penalties: $\text{PSI} = 100 \cdot E_{\text{norm}} \cdot (1 - \text{MVS}/100)$.
- **Calibrated Decision Framework:** Independently calibrated decision boundary ($\tau^* = 69.0$, $H_{\text{ref}}^* = 50.0$) achieving held-out separability on synthetic families.
- **Established Baseline Comparison:** Direct quantitative and qualitative comparisons against conventional entropy and Dropbox's `zxcvbn`.
- **Privacy-Preserving Dataset Ingestion Pipeline:** Capable of importing public breach research corpuses while aggregating statistics without displaying or logging individual credentials.

---

## Original Objectives & Fulfillment Status

| Original Project Objective | Implementation in System | Verifiable Evidence | Status |
|---|---|---|:---:|
| **Measure conventional password strength** | Theoretical search-space $S = N^L$ and Shannon entropy $H = L \cdot \log_2(N)$ | `password_analyzer/core.py`, `results/baseline_comparison.csv` | **COMPLETED** |
| **Detect dictionary and pattern risks** | Substring dictionary matcher with leetspeak reversal and structural patterns | `find_dictionary_base()`, `COMMON_WORDS` in `core.py` | **COMPLETED** |
| **Detect predictable mutations** | Four specific detectors: capitalization, leetspeak, numeric suffix, symbol suffix | `detect_mutations()`, `mutation_components()` | **COMPLETED** |
| **Develop Mutation Vulnerability Score** | Fixed-weight convex combination and empirical Laplace-smoothed $\text{MVS}_{\text{emp}}$ | `calculate_mvs()`, `calculate_empirical_mvs()`, `results/baseline_comparison.csv` | **COMPLETED** |
| **Combine factors into realistic assessment** | Normalized entropy penalized by mutation score: $\text{PSI} = 100 \cdot E_{\text{norm}} \cdot (1 - \text{MVS}/100)$ | `calculate_psi()`, `evaluate_calibrated_psi()`, `results/phase5_heldout_evaluation.csv` | **COMPLETED** |
| **Compare against conventional methods** | Comprehensive benchmark comparing conventional entropy, Dropbox `zxcvbn`, MVS, and PSI | `password_analyzer/baseline_comparator.py`, `results/BASELINE_COMPARISON_REPORT.md`, 8 publication figures | **COMPLETED** |

---

## Mathematical Framework

### 1. Theoretical Search Space & Shannon Entropy
For password length $L$ and alphabet pool $N \in \{10, 26, 36, 52, 62, 68, 94\}$:
$$S = N^L, \quad H = L \cdot \log_2(N)$$

> **CRITICAL SCIENTIFIC NOTE**: Theoretical Shannon entropy assumes independent uniform selection (i.e. rolling a fair $N$-sided die for each position). It measures the idealized size of the brute-force search space, **not** actual resistance against targeted dictionary attacks or rule-based cracking engines (Hashcat / John the Ripper).

### 2. Mutation Vulnerability Score (MVS)
$$\text{MVS}(p) = 100 \cdot \sum_{i=1}^5 w_i \cdot x_i(p), \quad \sum w_i = 1.0$$

Baseline convex weights:
- **Dictionary Base ($w_{\text{dict}} = 0.35$):** $x_1 = 1.0$ if a dictionary root word or base pattern is identified, else $0.0$.
- **Character Substitution ($w_{\text{sub}} = 0.20$):** $x_2 = 1.0$ if leetspeak substitution (e.g. `@` $\rightarrow$ `a`, `1` $\rightarrow$ `i`, `0` $\rightarrow$ `o`) is detected on the base, else $0.0$.
- **Numeric Suffix ($w_{\text{num}} = 0.20$):** $x_3 = 1.0$ if digits are appended after the base (before optional trailing symbols), else $0.0$.
- **Capitalization ($w_{\text{cap}} = 0.15$):** $x_4 = 1.0$ for TitleCase / initial capital, $0.7$ for mixed-case, else $0.0$.
- **Symbol Suffix ($w_{\text{sym}} = 0.10$):** $x_5 = 1.0$ if punctuation / symbols are appended at the end of the base, else $0.0$.

**Strict Safety Rule for Random Passwords:**
If no dictionary base or structural pattern is present (e.g. `vQ7mK2xR9zP4`), all mutation indicators $x_i = 0.0$, yielding $\text{MVS} = 0.0$. Random passwords are never penalized for character class diversity.

### 3. Empirical Probability Model (Laplace Smoothing & Surprisal)
Empirical frequency estimation grounded in observed training distributions:
$$\hat{p}_i = \frac{k_i + 1}{n + 2}, \quad I_i = -\log_2(\hat{p}_i) \text{ bits}$$

$$\text{MVS}_{\text{emp}}(p) = 100 \cdot \frac{\sum w_i \hat{p}_i x_i(p)}{\sum w_i x_i(p)}$$
Common habits (e.g. TitleCase, single digit suffixes) carry low surprisal ($I \approx 1.2$ bits), while rare mutations carry higher surprisal.

### 4. Password Security Index (PSI)
$$E_{\text{norm}} = \min\left(\frac{H}{H_{\text{ref}}}, 1.0\right), \quad \text{PSI} = 100 \cdot E_{\text{norm}} \cdot \left(1 - \frac{\text{MVS}}{100}\right)$$
PSI is strictly bounded in $[0.0, 100.0]$.

### 5. Reference Entropy ($H_{\text{ref}}$) Configurations
The project distinguishes two distinct $H_{\text{ref}}$ settings:
1. **Interactive Default ($H_{\text{ref}} = 80.0\text{ bits}$):** Represents conventional target strength for general human-memorizable master passwords.
2. **Phase 5 Calibrated Benchmark ($H_{\text{ref}}^* = 50.0\text{ bits}$, $\tau^* = 69.0$):** Empirically calibrated decision boundary for binary classification:
$$\text{Class}(p) = \begin{cases} \text{Low Vulnerability (Synthetic Random-like Control)} & \text{if } \text{PSI}_{\text{cal}}(p) \ge 69.0 \\ \text{Predictable Mutation (Vulnerable Family)} & \text{if } \text{PSI}_{\text{cal}}(p) < 69.0 \end{cases}$$

---

## Baseline Comparison Model (Dropbox zxcvbn)

The system integrates a modular, local evaluation against Dropbox's `zxcvbn` library (version 4.4+).
- **Zxcvbn Score:** Integer scale $0 \dots 4$ ($0$: too guessable, $4$: strong / unguessable).
- **Crack Times:** Offline slow hashing ($10^4$ guesses/sec) and online throttled attack estimates.
- **Independence:** The core MVS and PSI calculations remain completely independent of zxcvbn.
- **Graceful Fallback:** If zxcvbn is absent or receives empty input, the system safely falls back without raising unhandled exceptions.
- **Differentiation:** `zxcvbn` uses greedy context-free grammar parsing to estimate minimum guesses, while MVS/PSI explicitly isolates predictable mutation feature weights and discounts theoretical entropy.

---

## Canonical Benchmark Passwords

| Metric | `Password123!` | `vQ7mK2xR9zP4` | `P@ssword2026!` |
|---|:---:|:---:|:---:|
| **Length ($L$)** | 12 | 12 | 13 |
| **Character Pool ($N$)** | 94 | 62 | 94 |
| **Theoretical Entropy ($H$)** | 78.66 bits | 71.45 bits | 85.21 bits |
| **Conventional Score** | 100.0% | 81.2% | 100.0% |
| **Proposed MVS** | **80.0%** | **0.0%** | **100.0%** |
| **Proposed Empirical MVS** | **32.9%** | **0.0%** | **34.9%** |
| **Proposed PSI ($H_{\text{ref}}=80$)** | **19.7 / 100** | **89.3 / 100** | **0.0 / 100** |
| **Calibrated PSI ($H_{\text{ref}}=50$)** | **67.1 / 100** | **100.0 / 100** | **65.1 / 100** |
| **Existing Estimator (zxcvbn)** | 1 / 4 (4 seconds) | 4 / 4 (3 years) | 2 / 4 (17 minutes) |
| **Our Classification** | Predictable Mutation | Low Vulnerability | Predictable Mutation |

---

## Real / Public Research Dataset Pipeline

The project supports ingesting external research datasets (e.g. breach corpuses or public frequency tables) with **strict privacy preservation**:
- **Supported CSV Schema:**
  - `password_or_pattern`: String pattern or credential.
  - `source_or_group`: Corpus tag or source category.
  - `label`: Optional classification label.
- **Privacy Guarantee:** Individual passwords are never rendered in reports, logged to files, or displayed in the UI. Only aggregate population distributions are reported.
- **Strict Data Segregation:** Synthetic experimental data and real/public research data are segregated into explicit, distinct categories.

---

## Installation & Requirements

Ensure Python 3.10+ is installed.

```bash
# 1. Clone or navigate to the repository
cd password_mutation_project

# 2. Activate your virtual environment (recommended)
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
# source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Usage Instructions

### 1. Interactive Streamlit Web Application

Launch the interactive dashboard with 6 specialized modules:
```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501`.
Features:
- **Model Comparison:** 5-part comparative analysis with conventional score, zxcvbn metrics, crack times, and human-readable causal explanations.
- **Research Benchmark:** Side-by-side comparison of the three canonical benchmark passwords (`Password123!`, `vQ7mK2xR9zP4`, `P@ssword2026!`).
- **Empirical Probabilities & Surprisal:** Detailed breakdown of Laplace-smoothed frequencies and surprisal bits.
- **Baseline Visualizations:** Interactive gallery of all 8 high-resolution 300 DPI comparative figures.
- **Public Research Dataset:** Privacy-preserving CSV uploader and telemetry extractor.
- **Mathematical Model Details:** Complete LaTeX formulations for Phase 1 to Phase 5.

### 2. Command Line Interface (CLI)

Analyze any candidate password directly from the terminal:
```bash
python main.py "Password123!"
python main.py "vQ7mK2xR9zP4"
python main.py "P@ssword2026!"
```

### 3. Automated Experiments & Baseline Benchmark

Run the full experimental suite and generate all CSV datasets and publication figures:
```bash
python experiments.py
```
Output results summary on synthetic benchmark corpus ($N=330$):
- **Proposed PSI:** Accuracy: `0.9788`, Precision: `1.0000`, Recall: `0.9333`, F1: `0.9655`, ROC-AUC: `1.0000`, PR-AUC: `1.0000`
- **Proposed MVS:** Accuracy: `1.0000`, Precision: `1.0000`, Recall: `1.0000`, F1: `1.0000`, ROC-AUC: `1.0000`, PR-AUC: `1.0000`
- **Dropbox zxcvbn:** Accuracy: `0.9242`, Precision: `0.8077`, Recall: `1.0000`, F1: `0.8936`, ROC-AUC: `0.9937`, PR-AUC: `0.9780`
- **Conventional Entropy:** Accuracy: `0.8000`, Precision: `0.6211`, Recall: `0.9524`, F1: `0.7519`, ROC-AUC: `0.9365`, PR-AUC: `0.8913`

Generated artifacts:
- `results/baseline_comparison.csv`
- `results/BASELINE_COMPARISON_REPORT.md`
- `results/baseline_*.png` (8 publication figures)

### 4. Running Pytest Unit Tests

Run the complete 52-test unit test suite covering all mathematical calculations, mutation detectors, boundary conditions, edge cases, and regression tests:
```bash
pytest -v
```

---

## Project Directory Structure

```
password_mutation_project/
├── app.py                                   # Streamlit web application (6 modules)
├── main.py                                  # CLI runner & interactive tester
├── experiments.py                           # Full experiment pipeline (Phases 1-5 + Baseline)
├── requirements.txt                         # Python dependencies
├── pyproject.toml                           # Package and pytest configuration
├── README.md                                # Comprehensive project guide & documentation
│
├── password_analyzer/                       # Core analysis package
│   ├── __init__.py                          # Public API exports
│   ├── core.py                              # Search space, entropy, MVS, PSI, calibration
│   ├── baseline_comparator.py               # Dropbox zxcvbn comparator & benchmark suite
│   ├── dataset_pipeline.py                  # Public research dataset privacy pipeline
│   ├── experiment_runner.py                 # Baseline experiment benchmark & figure generator
│   └── cli.py                               # Command-line interface logic
│
├── tests/
│   └── test_core.py                         # 52 comprehensive pytest unit tests
│
├── data/
│   ├── synthetic_password_dataset_phase3.csv # Research evaluation corpus (330 passwords)
│   ├── example_passwords.csv                # Example password dataset
│   ├── phase5_family_disjoint_calibration_split.csv # Calibration split (6 root families, N=180)
│   ├── phase5_family_disjoint_eval_split.csv        # Disjoint eval split (9 distinct root families, N=180)
│   └── public_research_dataset_example.csv  # Example public research schema
│
├── docs/
│   └── MATHEMATICAL_MODEL.md                # Complete mathematical & analytical specification
│
├── results/
│   ├── baseline_comparison.csv              # Benchmark comparison across 330 samples
│   ├── BASELINE_COMPARISON_REPORT.md        # Detailed baseline comparison report
│   └── baseline_*.png                       # 8 publication-quality 300 DPI figures
│
└── final_submission/
    ├── Password_Strength_Predictable_Mutation_Final_Report.docx  # Formal DOCX academic report
    ├── Password_Strength_Predictable_Mutation_Presentation.pptx  # 20-slide academic presentation
    └── PROJECT_SUMMARY.md                   # Executive deliverables audit
```

---

## Formal Academic Limitations & Ethical Disclaimers

1. **Experimental Academic Metric:** MVS and PSI are experimental academic metrics formulated to explore predictable mutation structures. They do **not** constitute official NIST SP 800-63B guidelines, ISO/IEC security standards, or formal cryptographic proofs.
2. **Synthetic Dataset Scope & Circularity:** Evaluation was conducted on a controlled synthetic corpus ($N=330$). Because synthetic labels are assigned via predefined mutation templates, high accuracy reflects model consistency with known mutation rules rather than unconstrained real-world generalization. True wild-world efficacy requires evaluation on large independent breach corpuses.
3. **Cracking Work Factor vs. Heuristic Scoring:** A low PSI indicates predictable structure according to the model's mutation ruleset; it does not guarantee cracking times under specialized distributed GPU password recovery clusters.
4. **Dictionary Coverage Dependency:** The accuracy of the dictionary base detector depends on the underlying lexicon. Unseen words or rare foreign words will not be flagged as dictionary bases without expanding the lexicon.
5. **Mutation Rule Scope:** The current implementation models five prevalent mutation families. Complex obfuscations (e.g., phonetic leetspeak, multi-word passphrases, keyboard shifts) require generalized NLP grammar models.
6. **Privacy & Deployment Safeguards:** When running locally (`streamlit run app.py`), analysis executes entirely within the user's local Python process. In hosted public deployments (Streamlit Cloud), inputs are processed ephemerally in-memory by the application container without database persistence or logging. Users must never submit real-world credentials to any public demonstration.
