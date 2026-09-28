# Phase 4 — Parameter Sensitivity and Stability Analysis

## 1. Objective

Phase 4 tests whether the proposed Password Security Index (PSI) is highly dependent on
arbitrary model parameters.

Two parameter families are varied:

1. Mutation weights.
2. Reference entropy H_ref.

This is a sensitivity analysis, not a claim that any particular parameter setting is the
correct universal setting.

## 2. Weight profiles

The following explicit profiles were tested:

- Baseline
- Dictionary-heavy
- Mutation-heavy
- Equal
- Suffix-heavy

All profiles sum to 1.

## 3. Reference entropy

H_ref values tested:

    40, 50, 60, 70, 80, 90, 100, 120, 140 bits

The project formula remains:

    E_norm = min(H / H_ref, 1)

    PSI = 100 * E_norm * (1 - MVS/100)

## 4. Main sensitivity results

At the baseline parameter setting (H_ref = 80), the mean PSI separation between the
synthetic random-like group and the mutation-family group is:

    51.2991 points

Across the complete weight/H_ref grid, the observed mean PSI gap ranges from:

    33.2650 to 51.9215

These are properties of the current synthetic dataset, not general population estimates.

## 5. Weight sensitivity at H_ref = 80

  weight_profile  mutation_mean_mvs  mutation_mean_psi  random_mean_mvs  random_mean_psi  mean_psi_gap   psi_min  psi_max
        Baseline          34.037052          37.041251              0.0        88.340344     51.299092 19.998106    100.0
Dictionary-heavy          33.236692          37.515002              0.0        88.340344     50.825342 19.998106    100.0
  Mutation-heavy          35.089779          36.418863              0.0        88.340344     51.921481 19.998106    100.0
           Equal          34.753768          36.626927              0.0        88.340344     51.713417 19.998106    100.0
    Suffix-heavy          32.953246          37.710663              0.0        88.340344     50.629681 19.998106    100.0

## 6. H_ref sensitivity for baseline weights

weight_profile  H_ref  mutation_mean_mvs  random_mean_mvs  mutation_mean_psi  random_mean_psi  psi_mean_gap_random_minus_mutation  mutation_psi_std  random_psi_std
      Baseline     40          34.037052              0.0          62.234768       100.000000                           37.765232          6.497364        0.000000
      Baseline     50          34.037052              0.0          55.885244        99.795631                           43.910387          9.627925        1.117304
      Baseline     60          34.037052              0.0          48.852343        97.465576                           48.613233         10.663917        5.575356
      Baseline     70          34.037052              0.0          42.294719        93.474769                           51.180050          9.891871       10.202231
      Baseline     80          34.037052              0.0          37.041251        88.340344                           51.299092          8.732636       13.741453
      Baseline     90          34.037052              0.0          32.925557        82.626177                           49.700620          7.762343       16.130558
      Baseline    100          34.037052              0.0          29.633001        76.252919                           46.619918          6.986109       16.818738
      Baseline    120          34.037052              0.0          24.694168        63.949626                           39.255459          5.821757       14.629765
      Baseline    140          34.037052              0.0          21.166429        54.813965                           33.647536          4.990078       12.539798

## 7. Ranking stability

The Spearman correlation measures whether changing parameters substantially changes the
relative ordering of the same synthetic passwords.

Observed correlation range against the baseline:

    minimum = 0.8209
    maximum = 1.0000

A high correlation means the ordering is relatively stable under that parameter change;
it does not prove that the ordering is correct in the real world.

## 8. Pairwise separation

For each parameter combination, the pairwise separation probability is the proportion of
random-like vs mutation-family pairs for which the random-like password receives the higher
PSI.

This is descriptive and specific to this synthetic experiment.

## 9. Interpretation

The sensitivity analysis provides evidence about whether the model's behaviour is stable
under reasonable parameter changes. If the qualitative separation remains present across
the tested configurations, that supports continuing the model-development process.

However, sensitivity alone cannot determine the correct weights or H_ref. Those parameters
should ultimately be selected using a documented calibration procedure and an independent
validation dataset.

## 10. Limitations

- Synthetic dataset.
- Small mutation dictionary.
- Simplified mutation rules.
- Hand-designed weight profiles.
- H_ref is a model parameter.
- No real-world cracking-time labels.
- No external benchmark validation.

## 11. Next step

Phase 5 should turn the prototype into an evaluation framework:

1. Define an independent labelled dataset.
2. Split it into calibration/training and held-out evaluation sets.
3. Select parameters only from the calibration split.
4. Evaluate the final fixed model on the held-out split.
5. Report classification and calibration metrics where labels permit.
6. Compare PSI against entropy/length-only baselines.
