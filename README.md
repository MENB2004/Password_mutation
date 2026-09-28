# Password Strength & Predictable Mutation Analysis

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
   - [Streamlit Web Application](#1-interactive-streamlit-web-application)
   - [Command Line Interface (CLI)](#2-command-line-interface-cli)
   - [Automated Experiments & Baseline Benchmark](#3-automated-experiments--baseline-benchmark)
   - [Running Pytest Unit Tests](#4-running-pytest-unit-tests)
9. [Project Directory Structure](#project-directory-structure)
10. [Formal Academic Limitations & Ethical Disclaimers](#formal-academic-limitations--ethical-disclaimers)

---

## Project Overview & Key Contributions

Conventional password metrics rely heavily on **length** ($L$) and **character pool diversity** ($N$), evaluating theoretical entropy as $H = L \cdot \log_2(N)$. However, human password generation is notoriously non-random: users almost invariably start from a semantic root word (dictionary word, name, or concept) and apply predictable transformations (capitalizing the initial letter, substituting leetspeak symbols like `@` for `a` or `1` for `i`, and appending numeric years or exclamation marks). 

Conventional entropy assessments systematically **overestimate** the security of such passwords (giving them 70–85+ bits of entropy). 

This project introduces:
- **Mutation Vulnerability Score (MVS):** A structured metric quantifying five predictable construction vectors.
- **Empirical Probability Model:** Laplace-smoothed empirical frequencies and information surprisal ($I = -\log_2(\hat{p})$).
- **Password Security Index (PSI):** A penalized security metric balancing entropy with predictable mutation penalties.
- **Calibrated Decision Framework:** Independently calibrated decision boundary ($\tau = 69.0$, $H_{\text{ref}} = 50.0$) achieving 100% held-out separability on synthetic families.
- **Established Baseline Comparison:** Direct quantitative and qualitative comparisons against conventional entropy and Dropbox's `zxcvbn`.
- **Privacy-Preserving Dataset Ingestion Pipeline:** Capable of importing public breach research corpuses while aggregating statistics without displaying or logging individual credentials.

---

## Original Objectives & Fulfillment Status

| Original Project Objective | Implementation in System | Verifiable Evidence | Status |
|---|---|---|:---:|
| **Measure conventional password strength** | Theoretical search-space $S = N^L$ and Shannon entropy $H = L \cdot \log_2(N)$ | `password_analyzer/core.py`, `results/baseline_comparison.csv` | **COMPLETED** |
| **Detect dictionary and pattern risks** | Levenshtein & substring dictionary matcher with leetspeak reversal | `find_dictionary_base()`, `results/phase2_synthetic_dataset.csv` | **COMPLETED** |
| **Detect predictable mutations** | Four specific detectors: capitalization, leetspeak, numeric suffix, symbol suffix | `detect_mutations()`, `mutation_components()` | **COMPLETED** |
| **Develop Mutation Vulnerability Score** | Fixed-weight convex combination and empirical Laplace-smoothed $\text{MVS}_{\text{emp}}$ | `calculate_mvs()`, `calculate_empirical_mvs()`, `results/empirical_mutation_probabilities.csv` | **COMPLETED** |
| **Combine factors into realistic assessment** | Normalized entropy penalized by mutation score: $\text{PSI} = 100 \cdot E_{\text{norm}} \cdot (1 - \text{MVS}/100)$ | `calculate_psi()`, `evaluate_calibrated_psi()`, `results/phase5_heldout_evaluation.csv` | **COMPLETED** |
| **Compare against conventional methods** | Comprehensive benchmark comparing conventional entropy, Dropbox `zxcvbn`, MVS, and PSI | `password_analyzer/baseline_comparator.py`, `results/BASELINE_COMPARISON_REPORT.md`, 8 publication figures | **COMPLETED** |

---

## Mathematical Framework

### 1. Theoretical Search Space & Shannon Entropy
For password length $L$ and alphabet pool $N \in \{10, 26, 36, 52, 62, 68, 94\}$:
$$S = N^L, \quad H = L \cdot \log_2(N)$$

### 2. Mutation Vulnerability Score (MVS)
$$\text{MVS}(p) = 100 \cdot \sum_{i=1}^5 w_i \cdot x_i(p), \quad \sum w_i = 1$$
Baseline weights: Dictionary Base ($0.35$), Substitution ($0.20$), Numeric Suffix ($0.20$), Capitalization ($0.15$), Symbol Suffix ($0.10$).

### 3. Empirical Probability Model (Laplace Smoothing & Surprisal)
$$\hat{p}_i = \frac{k_i + 1}{n + 2}, \quad I_i = -\log_2(\hat{p}_i) \text{ bits}$$
$$\text{MVS}_{\text{emp}}(p) = 100 \cdot \frac{\sum w_i \hat{p}_i x_i(p)}{\sum w_i x_i(p)}$$

### 4. Password Security Index (PSI)
$$E_{\text{norm}} = \min\left(\frac{H}{H_{\text{ref}}}, 1.0\right), \quad \text{PSI} = 100 \cdot E_{\text{norm}} \cdot \left(1 - \frac{\text{MVS}}{100}\right)$$

### 5. Independent Calibration & Decision Boundary (Phase 5)
- Reference entropy: $H_{\text{ref}}^* = 50.0 \text{ bits}$
- Decision threshold: $\tau^* = 69.0$
$$\text{Class}(p) = \begin{cases} \text{Low Vulnerability (Synthetic Random Control)} & \text{if } \text{PSI}(p) \ge 69.0 \\ \text{Predictable Mutation (Vulnerable Family)} & \text{if } \text{PSI}(p) < 69.0 \end{cases}$$

---

## Baseline Comparison Model (Dropbox zxcvbn)

The system integrates a modular, local evaluation against Dropbox's `zxcvbn` library (version 4.5.0).
- **Zxcvbn Score:** Integer scale $0 \dots 4$ ($0$: too guessable, $4$: strong / unguessable).
- **Crack Times:** Offline fast hashing ($10^{10}$ guesses/sec) and online throttled attack estimates.
- **Guesses:** Minimum entropy match search based on context-free grammars and spatial adjacency.
- **Evaluation Benchmark:** Evaluated across the 330 synthetic passwords in `results/baseline_comparison.csv`.

---

## Canonical Benchmark Passwords

| Metric | `Password123!` | `vQ7mK2xR9zP4` | `P@ssword2026!` |
|---|:---:|:---:|:---:|
| **Length ($L$)** | 12 | 12 | 13 |
| **Character Pool ($N$)** | 94 | 62 | 94 |
| **Theoretical Entropy ($H$)** | 78.66 bits | 71.45 bits | 85.21 bits |
| **Conventional Score** | 98.3% | 89.3% | 100.0% |
| **Proposed MVS** | **85.0%** | **0.0%** | **95.0%** |
| **Proposed Empirical MVS** | **37.0%** | **0.0%** | **37.9%** |
| **Proposed PSI** | **11.8 / 100** | **89.3 / 100** | **4.3 / 100** |
| **Existing Estimator (zxcvbn)** | 0 / 4 (Instant) | 4 / 4 (Centuries) | 2 / 4 (Hours) |
| **Our Classification** | Predictable Mutation | Low Vulnerability | Predictable Mutation |

---

## Real / Public Research Dataset Pipeline

The project supports ingesting external research datasets (e.g. breach corpuses or public frequency tables) with **strict privacy preservation**:
- **Supported CSV Schema:**
  - `password_or_pattern`: String pattern or credential.
  - `source_or_group`: Corpus tag or source category.
  - `label`: Optional classification label.
- **Privacy Guarantee:** Individual passwords are never rendered in reports, logged to files, or displayed in the UI. Only aggregate mutation frequencies ($f_D, f_C, f_S, f_N, f_Y$) are reported.
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
- **Password Analyzer:** Real-time entropy, mutation decomposition, MVS, surprisal bits, and PSI.
- **Model Comparison:** 5-part comparative analysis with conventional score, zxcvbn metrics, crack times, and human-readable causal explanations.
- **Research Benchmark:** Side-by-side comparison of the three canonical benchmark passwords (`Password123!`, `vQ7mK2xR9zP4`, `P@ssword2026!`).
- **Phase 1-5 Research Data:** Interactive tables for all 330 synthetic samples, statistical tests, and held-out calibration.
- **Baseline Visualizations:** Interactive gallery of all 8 high-resolution 300 DPI comparative figures.
- **Public Research Dataset:** Privacy-preserving CSV uploader and telemetry extractor.

### 2. Command Line Interface (CLI)

Analyze any candidate password directly from the terminal:
```bash
python -m password_analyzer "Password123!"
python -m password_analyzer "P@ssword2026!"
python -m password_analyzer "vQ7mK2xR9zP4"
```

### 3. Automated Experiments & Baseline Benchmark

Run the full experimental suite and generate all CSV datasets and publication figures:
```bash
python experiments.py
```
This executes:
- Phase 2 synthetic dataset generation ($N=330$).
- Phase 3 empirical probability estimation, Laplace smoothing, and statistical validation.
- Phase 4 weight profile sensitivity and rank stability analysis.
- Phase 5 calibration and held-out evaluation.
- Baseline comparison benchmark against Dropbox `zxcvbn` and conventional entropy.
- Generation of 8 publication-quality figures in `results/`.

### 4. Running Pytest Unit Tests

Run the complete 23-test unit test suite covering all mathematical calculations, mutation detectors, threshold classifiers, baseline comparators, and edge cases:
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
│   └── experiment_runner.py                 # Baseline experiment benchmark & figure generator
│
├── tests/
│   └── test_core.py                         # 23 comprehensive pytest unit tests
│
├── data/
│   └── public_research_dataset_example.csv  # Example public research schema
│
├── docs/
│   ├── MATHEMATICAL_MODEL.md                # Complete mathematical & analytical specification
│   ├── original_project_description.txt     # Original project requirements
│   └── summary.txt                          # Comprehensive architecture explanation
│
├── results/
│   ├── baseline_comparison.csv              # Benchmark comparison across 330 samples
│   ├── BASELINE_COMPARISON_REPORT.md        # Detailed baseline comparison report
│   ├── baseline_*.png                       # 8 publication-quality 300 DPI figures
│   ├── phase2_synthetic_dataset.csv         # Synthetic evaluation corpus
│   ├── empirical_mutation_probabilities.csv # Laplace-smoothed empirical mutation frequencies
│   ├── phase3_statistical_validation.csv    # Mann-Whitney U, Spearman, and effect sizes
│   ├── phase4_weight_sensitivity.csv        # Sensitivity across 5 weight profiles
│   └── phase5_heldout_evaluation.csv        # Held-out calibration and decision metrics
│
└── final_submission/
    ├── Password_Strength_Predictable_Mutation_Final_Report.docx  # Formal DOCX academic report
    ├── Password_Strength_Predictable_Mutation_Presentation.pptx  # 20-slide academic presentation
    └── PROJECT_SUMMARY.md                   # Executive deliverables and objectives audit
```

---

## Formal Academic Limitations & Ethical Disclaimers

1. **Experimental Academic Metric:** MVS and PSI are experimental academic metrics formulated to explore predictable mutation structures. They do **not** constitute official NIST SP 800-63B guidelines, ISO/IEC security standards, or formal cryptographic proofs.
2. **Synthetic Dataset Scope:** Evaluation was conducted on a controlled synthetic corpus ($N=330$). Synthetic distributions allow controlled isolation of variables, but do not claim to reflect the exhaustive distribution of global real-world breach corpuses.
3. **Cracking Work Factor vs. Heuristic Scoring:** A low PSI indicates predictable structure according to the model's mutation ruleset; it does not guarantee cracking times under specialized distributed GPU password recovery clusters.
4. **Dictionary Coverage Dependency:** The accuracy of the dictionary base detector depends on the underlying lexicon. Unseen words or rare foreign words will not be flagged as dictionary bases without expanding the lexicon.
5. **Mutation Rule Scope:** The current implementation models four prevalent mutation families. Complex obfuscations (e.g., phonetic leetspeak, anagrams, multi-word passphrases) require generalized NLP grammar rules.
6. **Privacy & Ethical Safeguards:** Real-world credentials must never be submitted over unencrypted networks or stored in cleartext. The system processes all inputs locally and enforces strict privacy-preserving aggregation for research datasets.
