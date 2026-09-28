# Phase 3 — Empirical Probability Model & Statistical Validation

## Modelling correction

Generic uppercase letters, digits, and symbols are not automatically treated as predictable
mutations. A mutation is counted only when it is linked to a detected dictionary-like base.
This prevents random-looking controls from receiving mutation vulnerability merely because
they contain diverse characters.

## Probability model

For a mutation pattern among dictionary-based examples:

p_hat_i = (k_i + 1) / (n_dictionary + 2)

For dictionary-base prevalence:

p_hat_D = (k_D + 1) / (n + 2)

Information content:

I_i = -log2(p_hat_i)

## Empirical MVS

MVS_emp = 100 * [Σ(w_i p_hat_i x_i)] / [Σ(w_i x_i)]

Initial project weights:
- capitalization 0.15
- substitution 0.20
- numeric suffix 0.20
- symbol suffix 0.10
- dictionary base 0.35

These weights remain explicit design parameters rather than learned claims.

## PSI

E_norm = min(H / 80, 1)

PSI_emp = 100 * E_norm * (1 - MVS_emp/100)

The 80-bit reference is a project parameter.

## Conditional empirical probabilities

             pattern  count  denominator  empirical_probability  smoothed_probability  surprisal_bits
      capitalization     45          105               0.428571              0.429907        1.217905
        substitution     45          105               0.428571              0.429907        1.217905
      numeric_suffix     30          105               0.285714              0.289720        1.787271
       symbol_suffix     30          105               0.285714              0.289720        1.787271
dictionary_base_flag    105          330               0.318182              0.319277        1.647119

## Group statistics

                        label   n  mean_entropy  mean_empirical_mvs  mean_empirical_psi  median_empirical_psi  std_empirical_psi
               capitalization  15     37.622902           35.246594           30.452638             27.684217           4.870564
capitalization+numeric_suffix  15     55.175552           35.573134           44.434849             47.951276          10.166618
 capitalization+symbol_suffix  15     48.581612           34.200822           39.957877             36.803308           5.549925
              dictionary_only  15     31.022902           31.927711           26.397500             23.997727           4.221989
               numeric_suffix  15     48.597295           34.089630           40.038321             38.334563           7.163604
  substitution+numeric_suffix  15     49.660736           35.950599           39.759255             43.863564           7.521250
                symbol_suffix  15     44.520656           31.270878           38.248320             35.228715           5.312477
        synthetic_random_like 225     76.739551            0.000000           88.340344             96.755690          13.741453

## Statistical validation

                                comparison  mutation_n  random_n  mutation_mean_psi  random_mean_psi  mean_difference_random_minus_mutation  bootstrap_95ci_low  bootstrap_95ci_high  mann_whitney_u  mann_whitney_p  rank_biserial_effect  spearman_mvs_psi   spearman_p
Mutation families vs synthetic random-like         105       225          37.041251        88.340344                              51.299092           48.812953            53.830925             6.0    6.636927e-50              0.999492         -0.788117 4.158272e-71

The Mann–Whitney test is used as a non-parametric comparison between PSI distributions.
The bootstrap interval quantifies uncertainty in the difference between sample means under
resampling of this synthetic dataset.

## Interpretation

The corrected model keeps random character diversity separate from dictionary-linked
predictable mutation. In this controlled synthetic experiment, mutation-family examples
and random-like controls show different empirical MVS/PSI distributions.

This does not establish real-world cracking probabilities or prove that PSI predicts
attacker success. The dataset is synthetic, the dictionary is small, the mutation rules
are simplified, and the weights/reference entropy are project-defined.

## Limitations and next stage

A stronger validation should use a properly licensed research dataset with independent
labels, derive mutation frequencies from a training split, calibrate parameters without
using the test split, and evaluate on held-out data.
