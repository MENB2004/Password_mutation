# Mathematical Model: Password Strength & Predictable Mutation Analysis

This document provides a comprehensive mathematical specification of the analytical and empirical frameworks implemented in this research project, including theoretical search-space modeling, conventional Shannon entropy, predictable mutation detection, fixed-weight and empirical Mutation Vulnerability Scores (MVS), the Password Security Index (PSI), calibration/held-out validation, baseline comparison models, and formal academic limitations.

---

## 1. Search-Space Model

Let a candidate password $p$ have length $L = |p|$ characters drawn from an alphabet (character pool) $\Sigma$ of size $N = |\Sigma|$.

Under the assumption of independent and uniformly distributed character selection from $\Sigma$, the total size of the candidate search space $S$ is:

$$S = N^L$$

### Character Pool Estimation

The character pool size $N(p)$ is inferred from the presence of standard character sub-classes:

$$N(p) = \sum_{k \in \mathcal{K}} |\Sigma_k| \cdot \mathbb{I}(p \cap \Sigma_k \neq \emptyset)$$

where the standard sub-classes and cardinalities are:
- Lowercase alphabetical: $\Sigma_{\text{lower}} = \{a, \dots, z\}$, $|\Sigma_{\text{lower}}| = 26$
- Uppercase alphabetical: $\Sigma_{\text{upper}} = \{A, \dots, Z\}$, $|\Sigma_{\text{upper}}| = 26$
- Numeric digits: $\Sigma_{\text{digit}} = \{0, \dots, 9\}$, $|\Sigma_{\text{digit}}| = 10$
- Printable symbols: $\Sigma_{\text{symbol}} = \{!, @, \#, \dots\}$, $|\Sigma_{\text{symbol}}| = 32$

Thus, $N \in \{0, 10, 26, 36, 52, 62, 68, 94\}$.

---

## 2. Theoretical Shannon Entropy

Under the idealized assumption of uniform and independent character selection:

$$H(p) = \log_2(S) = L \cdot \log_2(N)$$

### The Theoretical Limitation of Conventional Entropy
Real human-generated passwords do **not** satisfy independence or uniformity. Humans construct passwords using semantic root words (dictionary words, names, concepts) combined with stereotypical mutation rules (capitalizing the initial letter, replacing letters with visual leetspeak homoglyphs, appending digits and punctuation symbols). Consequently, conventional entropy severely **overestimates** the real work factor of human passwords.

---

## 3. Predictable Mutation Indicators

For any password $p$, the analyzer evaluates five structured vulnerability indicators $x_i(p) \in [0, 1]$:

1. **Dictionary Base Indicator ($D$):**
   $$D(p) = \begin{cases} 1.0 & \text{if a root dictionary word } d \in \mathcal{D} \text{ or its leetspeak preimage is detected in } p \\ 0.0 & \text{otherwise} \end{cases}$$

2. **Capitalization Predictability ($C$):**
   $$C(p) = \begin{cases} 1.0 & \text{if } D(p) = 1 \text{ and } p \text{ begins with an uppercase letter (title-case)} \\ 0.7 & \text{if } D(p) = 1 \text{ and mixed uppercase letters occur within the base} \\ 0.0 & \text{otherwise} \end{cases}$$

3. **Character Substitution / Leetspeak Predictability ($S$):**
   $$S(p) = \begin{cases} 1.0 & \text{if } D(p) = 1 \text{ and substitutions from } \mathcal{M} \text{ are required to recover } d \in \mathcal{D} \\ 0.0 & \text{otherwise} \end{cases}$$
   where $\mathcal{M} = \{0 \mapsto o, 1 \mapsto i, 3 \mapsto e, 4 \mapsto a, @ \mapsto a, \$ \mapsto s, 5 \mapsto s, 7 \mapsto t\}$.

4. **Numeric Suffix Predictability ($N$):**
   $$N(p) = \begin{cases} 1.0 & \text{if } D(p) = 1 \text{ and trailing digits appear after the root word} \\ 0.0 & \text{otherwise} \end{cases}$$

5. **Symbol Suffix Predictability ($Y$):**
   $$Y(p) = \begin{cases} 1.0 & \text{if } D(p) = 1 \text{ and trailing punctuation symbols appear at the end} \\ 0.0 & \text{otherwise} \end{cases}$$

---

## 4. Weighted Mutation Vulnerability Score (MVS)

The baseline fixed-weight Mutation Vulnerability Score is defined as a linear convex combination normalized to $[0, 100]$:

$$\text{MVS}(p) = 100 \cdot \sum_{i=1}^5 w_i \cdot x_i(p)$$

where:
$$\sum_{i=1}^5 w_i = 1, \quad w_i \ge 0$$

### Weight Profiles (Phase 4 Sensitivity Analysis)

| Profile | Capitalization ($w_C$) | Substitution ($w_S$) | Numeric Suffix ($w_N$) | Symbol Suffix ($w_Y$) | Dictionary Base ($w_D$) |
|---|:---:|:---:|:---:|:---:|:---:|
| **Baseline** | 0.15 | 0.20 | 0.20 | 0.10 | **0.35** |
| **Dictionary-heavy** | 0.10 | 0.15 | 0.15 | 0.10 | **0.50** |
| **Mutation-heavy** | 0.20 | **0.25** | **0.25** | 0.10 | 0.20 |
| **Equal** | 0.20 | 0.20 | 0.20 | 0.20 | 0.20 |
| **Suffix-heavy** | 0.15 | 0.10 | **0.30** | **0.20** | 0.25 |

Phase 4 rank stability analysis confirmed that the Spearman rank correlation across profiles exceeds $\rho \ge 0.99$, demonstrating robust ordering across reasonable weighting variations.

---

## 5. Empirical Probability Model & Information Surprisal (Phase 3)

Rather than treating mutation components as arbitrary static weights, Phase 3 grounds component likelihoods in empirical observation using Laplace smoothing:

$$\hat{p}_i = \frac{k_i + 1}{n + 2}$$

where $k_i$ is the observed count of feature $i$, and $n$ is the effective sample size ($n_{\text{dictionary}} = 105$ for mutation components; $n_{\text{total}} = 330$ for dictionary base occurrence).

### Information Content / Surprisal

The surprisal (self-information in bits) measures the rarity of each feature:

$$I_i = -\log_2(\hat{p}_i)$$

### Empirical MVS Formula

$$\text{MVS}_{\text{emp}}(p) = 100 \cdot \frac{\sum_{i=1}^5 w_i \cdot \hat{p}_i \cdot x_i(p)}{\sum_{i=1}^5 w_i \cdot x_i(p)}$$

If no dictionary base is detected ($\sum w_i x_i = 0$), then $\text{MVS}_{\text{emp}} = 0.0$.

---

## 6. Password Security Index (PSI)

The proposed Password Security Index penalizes conventional entropy by the detected mutation vulnerability:

$$\text{PSI}(p) = 100 \cdot E_{\text{norm}}(p) \cdot \left(1 - \frac{\text{MVS}(p)}{100}\right)$$

where normalized entropy is:

$$E_{\text{norm}}(p) = \min\left(\frac{H(p)}{H_{\text{ref}}}, 1.0\right)$$

- $H_{\text{ref}}$: Reference entropy benchmark (bits).
- When $\text{MVS} = 0$: $\text{PSI} = 100 \cdot E_{\text{norm}}$ (no mutation penalty).
- When $\text{MVS} = 100$: $\text{PSI} = 0$ (entirely compromised by predictable construction).

---

## 7. Calibration & Held-Out Decision Model (Phase 5)

Using an independent calibration split, the model's hyper-parameters were calibrated:
- **Calibrated Reference Entropy:** $H_{\text{ref}}^* = 50.0 \text{ bits}$
- **Calibrated Decision Threshold:** $\tau^* = 69.0$

### Decision Rule
$$\text{Class}(p) = \begin{cases} \text{Low Vulnerability (Synthetic Random Control)} & \text{if } \text{PSI}(p) \ge \tau^* \\ \text{Predictable Mutation (Vulnerable Family)} & \text{if } \text{PSI}(p) < \tau^* \end{cases}$$

On the held-out evaluation dataset ($N = 100$), this decision rule achieved:
- Accuracy: **100.0%**
- ROC-AUC: **1.000**
- Average Precision (PR-AUC): **1.000**

---

## 8. Baseline Comparison Framework

To rigorously contextualize MVS and PSI, the system evaluates candidate passwords against established industry baselines:

### 1. Conventional Entropy Assessment
- Evaluates $H(p) = L \cdot \log_2(N)$ normalized to $[0, 100]$:
  $$\text{Score}_{\text{conventional}}(p) = \min\left(\frac{H(p)}{H_{\text{ref}}}, 1.0\right) \cdot 100$$
- **Limitation:** Fails to detect dictionary bases or leetspeak substitutions; rates `Password123!` and `P@ssword2026!` as high security simply due to diverse character sets.

### 2. Dropbox zxcvbn Estimator
- Grounded in context-free grammars, dictionary matching (30k+ words), spatial keyboard adjacency, repetition detection, and dynamic programming to find the minimum-entropy match sequence.
- **Metric:** Log-guesses $\log_{10}(\text{guesses})$ and categorical score $\in \{0, 1, 2, 3, 4\}$.
- **Normalized Score:** $\text{Score}_{\text{zxcvbn}} = \text{score} \times 25.0 \in [0, 100]$.

### 3. Comparison Synthesis: Canonical Benchmarks

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

## 9. Real / Public Research Dataset Ingestion Model

To support validation on external empirical password frequency distributions while preserving security and privacy:
1. **Schema Requirement:**
   - Input format: CSV with `password_or_pattern`, `source_or_group`, and `label`.
2. **Privacy-Preserving Aggregation:**
   - Raw individual passwords are **never** persisted to report artifacts, displayed in UIs, or rendered in figures.
   - The pipeline computes aggregate feature frequencies:
     - Dictionary base prevalence: $f_D = \frac{1}{M}\sum D(p_j)$
     - Capitalization prevalence: $f_C = \frac{1}{M}\sum C(p_j)$
     - Substitution prevalence: $f_S = \frac{1}{M}\sum S(p_j)$
     - Numeric suffix prevalence: $f_N = \frac{1}{M}\sum N(p_j)$
     - Symbol suffix prevalence: $f_Y = \frac{1}{M}\sum Y(p_j)$
3. **Data Segregation:**
   - Synthetic experimental datasets and real/public research datasets are strictly segregated in distinct namespaces (`SYNTHETIC DATA` vs `REAL/PUBLIC RESEARCH DATA`).

---

## 10. Formal Academic Limitations & Disclaimers

1. **Experimental Academic Metric:** MVS and PSI are academic research prototypes designed to illustrate predictable mutation phenomena. They are **not** NIST SP 800-63B standards, ISO/IEC standards, or formal cryptographic proofs.
2. **Synthetic Dataset Scope:** The experimental validation was conducted on a controlled synthetic corpus ($N=330$). While ideal for testing statistical separability and isolating mutation effects, synthetic distributions do not mirror the full linguistic diversity of global breach corpuses (e.g., RockYou, HaveIBeenPwned).
3. **Cracking Work-Factor vs. Theoretical Search Space:** A PSI score of 10/100 indicates high mutation vulnerability relative to the model's ruleset; it does **not** constitute an exact guarantee of cracking time under specialized hardware rigs.
4. **Dictionary Coverage Dependency:** The accuracy of $D(p)$ depends strictly on the dictionary lexicon $\mathcal{D}$. Words outside $\mathcal{D}$ will not trigger mutation indicators.
5. **Fixed Rule Scope:** The mutation engine focuses on four specific, widespread mutation patterns. More complex transformations (e.g., anagrams, phonetic slang, multi-word passphrases) require extended grammar-based parsing.
