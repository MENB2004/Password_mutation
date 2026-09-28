# Phase 2 — Experimental Dataset & Mathematical Analysis

## Dataset

A synthetic dataset of 330 password examples was generated. It contains controlled
dictionary/mutation families and random-like synthetic controls. No real user credentials
are included.

## Categories

                        label  samples  avg_length  avg_entropy_bits   avg_mvs   avg_psi
               capitalization       15    6.600000         37.622902 50.000000 23.514314
capitalization+numeric_suffix       15    9.266667         55.175552 90.000000  6.896944
 capitalization+symbol_suffix       15    7.600000         48.581612 60.000000 24.290806
              dictionary_only       15    6.600000         31.022902 35.000000 25.206108
               numeric_suffix       15    9.400000         48.597295 75.000000 15.186655
  substitution+numeric_suffix       15    8.600000         49.660736 75.000000 15.518980
                symbol_suffix       15    7.600000         44.520656 45.000000 30.607951
        synthetic_random_like      225   12.000000         76.739551  4.177778 84.652936

## Model

The project computes theoretical search space, entropy, Mutation Vulnerability Score (MVS),
and the experimental Password Security Index (PSI).

Entropy:

    H = L log2(N)

Mutation score:

    MVS = 100 Σ wi xi

Combined score:

    PSI = 100 E_norm (1 - MVS/100)

## Baseline comparison

The conventional baseline used in this experiment is deliberately simple: a 0–100 score
based only on password length and the number of character types. It is included as a
transparent comparison baseline, not as an industry-standard password meter.

                        label  avg_conventional_score   avg_psi   avg_mvs  avg_entropy  samples
               capitalization               45.625000 23.514314 50.000000    37.622902       15
capitalization+numeric_suffix               66.458333  6.896944 90.000000    55.175552       15
 capitalization+symbol_suffix               61.250000 24.290806 60.000000    48.581612       15
              dictionary_only               33.125000 25.206108 35.000000    31.022902       15
               numeric_suffix               54.375000 15.186655 75.000000    48.597295       15
  substitution+numeric_suffix               60.208333 15.518980 75.000000    49.660736       15
                symbol_suffix               48.750000 30.607951 45.000000    44.520656       15
        synthetic_random_like               82.666667 84.652936  4.177778    76.739551      225

## Interpretation

The synthetic experiment is designed to test the project's central hypothesis:
passwords with similar conventional character complexity can have different mutation
profiles, and explicitly modelling predictable construction can therefore change the
assessment.

The results should be treated as prototype evidence only. The current dataset is synthetic,
the dictionary is small, and the MVS weights are hand-selected initial hypotheses.
A stronger research version should use a properly licensed password dataset, estimate
mutation frequencies from data, document the sampling process, and validate the score
against an independently defined labelled benchmark.

## Files

- synthetic_password_dataset.csv
- dataset_summary.csv
- conventional_vs_proposed.csv
- weight_sensitivity.csv
- entropy_vs_mvs.png
- entropy_vs_psi.png
- mutation_frequency.png
- conventional_vs_psi.png
