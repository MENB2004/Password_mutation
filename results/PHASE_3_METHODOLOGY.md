# Phase 3 Methodology

### Step 1 — Generate controlled data
Create synthetic password families representing dictionary words, capitalization,
numeric suffixes, symbol suffixes, substitutions, combinations, and random-like controls.

### Step 2 — Extract binary features
For each password, create indicators for the mutation patterns.

### Step 3 — Estimate probabilities
Use Laplace-smoothed empirical frequency:

p_hat = (k+1)/(n+2)

### Step 4 — Compute information content
For each pattern:

I = -log2(p_hat)

### Step 5 — Compute empirical MVS
For each password, combine the empirical prevalence of its detected patterns with the
project weights.

### Step 6 — Compute PSI
Normalize entropy against the project reference H_ref and discount it using empirical MVS.

### Step 7 — Validate
Compare PSI distributions between mutation families and random-like controls using a
non-parametric Mann–Whitney test. Estimate uncertainty in the mean difference using
bootstrap resampling.

### Step 8 — Sensitivity
Repeat the model with alternative weights and reference entropy values before drawing
any conclusions.

### Reproducibility
All synthetic examples are generated with a fixed random seed of 42.
