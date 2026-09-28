import os
from pathlib import Path
import pandas as pd
import streamlit as st

from password_analyzer.core import (
    analyze_password,
    DEFAULT_WEIGHTS,
    DEFAULT_EMPIRICAL_PROBABILITIES,
    DEFAULT_SURPRISAL_BITS,
    WEIGHT_PROFILES,
    CALIBRATED_H_REF,
    CALIBRATED_PSI_THRESHOLD,
)
from password_analyzer.baseline_comparator import (
    compare_password,
    compare_benchmark_passwords,
    build_comparison_dataframe,
    get_existing_estimator_assessment,
)
from password_analyzer.dataset_pipeline import (
    import_research_dataset,
    create_example_public_research_dataset,
)

st.set_page_config(
    page_title="Password Mutation & Empirical Security Analyzer",
    page_icon="🔐",
    layout="wide",
)

st.title("🔐 Password Strength & Predictable Mutation Analysis")
st.caption(
    "Mathematical model combining theoretical search space, entropy, predictable mutations, "
    "empirical probability estimation (Phase 3), and held-out calibration (Phase 5)."
)

st.info(
    "**Local Analysis Only**: All analysis runs locally on your machine. "
    "Do not enter actual real-world account credentials. Use safe synthetic or test examples."
)

# Sidebar: Configuration
st.sidebar.header("⚙️ Model Configuration")

# Preset selection
profile_name = st.sidebar.selectbox(
    "Weight Profile Preset (Phase 4)",
    options=list(WEIGHT_PROFILES.keys()) + ["Custom"],
    index=0,
)

if profile_name != "Custom":
    active_weights = WEIGHT_PROFILES[profile_name].copy()
    st.sidebar.caption(f"Loaded '{profile_name}' weight preset.")
else:
    active_weights = DEFAULT_WEIGHTS.copy()

with st.sidebar.expander("Adjust Mutation Weights", expanded=(profile_name == "Custom")):
    weights = {}
    for key, default in active_weights.items():
        weights[key] = st.slider(
            key.replace("_", " ").title(),
            min_value=0.0,
            max_value=1.0,
            value=float(default),
            step=0.05,
        )

# Reference entropy configuration
st.sidebar.subheader("Entropy Normalization")
use_calibrated = st.sidebar.checkbox(
    f"Use Phase 5 Calibrated H_ref ({CALIBRATED_H_REF:.0f} bits)",
    value=False,
    help="Locks H_ref to 50 bits as selected during independent calibration in Phase 5.",
)

if use_calibrated:
    h_ref = CALIBRATED_H_REF
    st.sidebar.info(f"H_ref locked to calibrated value: {CALIBRATED_H_REF:.0f} bits")
else:
    h_ref = st.sidebar.slider("Reference entropy H_ref (bits)", 40, 160, 80, step=5)

# Example quick-fill buttons
st.sidebar.subheader("Quick Example Passwords")
sample_passwords = [
    "Password123!",
    "P@ssword2026!",
    "vQ7mK2xR9zP4",
    "password",
    "Welcome2026",
    "w3lc0m3!",
]
selected_sample = st.sidebar.selectbox("Choose a sample password", [""] + sample_passwords)

# Top Navigation Tabs
main_tabs = st.tabs([
    "🔬 Model Comparison & Deep Dive",
    "⚖️ Three-Password Benchmark Comparison",
    "📊 Empirical Probabilities & Surprisal",
    "📈 Publication Visualizations",
    "📁 Public Research Dataset Pipeline",
    "📐 Mathematical Model Details",
])

default_input = selected_sample if selected_sample else "Password123!"

# TAB 1: MODEL COMPARISON & DEEP DIVE (Task 6)
with main_tabs[0]:
    st.header("🔬 Model Comparison")
    st.markdown("Evaluate any synthetic test password across conventional entropy, Dropbox `zxcvbn`, and proposed MVS / PSI.")

    password_input = st.text_input(
        "Enter a test password to analyze:",
        value=default_input,
        type="default",
        placeholder="e.g. Password123! or vQ7mK2xR9zP4",
        key="main_password_input",
    )

    if password_input:
        comp = compare_password(password_input, weights=weights, h_ref=h_ref)
        analysis = analyze_password(password_input, weights=weights, h_ref=h_ref)

        # High-level Metrics Row
        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Entropy (H)", f"{comp.entropy:.2f} bits", help="H = L * log2(N)")
        m2.metric("Fixed MVS", f"{comp.mvs:.1f}/100", help="Baseline weighted mutation score")
        m3.metric("Proposed PSI", f"{comp.psi:.1f}/100", help="Normalized entropy discounted by MVS")
        m4.metric(
            f"Existing Estimator",
            f"{comp.existing_estimator_score}/4",
            help=f"{comp.existing_estimator_name}: {comp.existing_estimator_category}",
        )
        m5.metric("Empirical PSI", f"{comp.empirical_psi:.1f}/100", help="PSI using empirical mutation weights")

        st.markdown("---")

        col_left, col_right = st.columns(2)

        # 1. PASSWORD ANALYSIS
        with col_left:
            st.subheader("1. PASSWORD ANALYSIS")
            st.write(f"• **Length ($L$):** `{comp.length}` characters")
            classes_detected = [k for k, v in analysis.character_types.items() if v]
            st.write(f"• **Character classes:** {', '.join(f'`{c}`' for c in classes_detected)}")
            st.write(f"• **Character pool ($N$):** `{comp.character_pool}` possible characters")
            st.write(f"• **Search space ($S = N^L$):** `{analysis.search_space:,}` combinations")
            st.write(f"• **Theoretical entropy ($H$):** `{comp.entropy:.2f}` bits")

        # 2. PREDICTABLE MUTATION ANALYSIS
        with col_right:
            st.subheader("2. PREDICTABLE MUTATION ANALYSIS")
            st.write(f"• **Dictionary base:** `{analysis.dictionary_base or 'None detected'}`")
            st.write(f"• **Capitalization:** `{'Detected' if 'capitalization' in analysis.mutations else 'None'}` (score: {analysis.mutation_components.get('capitalization', 0.0):.2f})")
            st.write(f"• **Substitution:** `{'Detected' if 'character substitution' in analysis.mutations else 'None'}` (score: {analysis.mutation_components.get('substitution', 0.0):.2f})")
            st.write(f"• **Numeric suffix:** `{'Detected' if 'numeric suffix' in analysis.mutations else 'None'}` (score: {analysis.mutation_components.get('numeric_suffix', 0.0):.2f})")
            st.write(f"• **Symbol suffix:** `{'Detected' if 'symbol suffix' in analysis.mutations else 'None'}` (score: {analysis.mutation_components.get('symbol_suffix', 0.0):.2f})")
            st.write(f"• **Mutation Vulnerability Score (MVS):** `{comp.mvs:.1f}/100`")
            st.write(f"• **Empirical MVS (Phase 3):** `{comp.empirical_mvs:.1f}/100`")

        st.markdown("---")
        col_sec, col_base = st.columns(2)

        # 3. SECURITY INDEX
        with col_sec:
            st.subheader("3. SECURITY INDEX")
            st.write(f"• **Normalized entropy ($E_{{\\text{{norm}}}}$):** `{analysis.entropy_normalized:.4f}`")
            st.write(f"• **Password Security Index (PSI):** `{comp.psi:.1f}/100`")
            st.write(f"• **Risk category:** **{analysis.risk_category}**")
            st.write(f"• **Calibrated PSI ($H_{{\\text{{ref}}}}=50$):** `{comp.calibrated_psi:.1f}/100`")
            st.write(f"• **Calibrated classification:** `{comp.our_classification}`")

        # 4. BASELINE COMPARISON
        with col_base:
            st.subheader("4. BASELINE COMPARISON")
            st.write(f"• **Conventional entropy assessment:** `{comp.conventional_score:.1f}/100` ({comp.entropy:.2f} bits)")
            st.write(f"• **Existing estimator ({comp.existing_estimator_name}):** `{comp.existing_estimator_score}/4` — *{comp.existing_estimator_category}*")
            st.write(f"• **Estimated offline crack time:** `{comp.existing_estimator_crack_time_display}` (log10 guesses: {comp.existing_estimator_guesses_log10:.2f})")
            st.write(f"• **Proposed PSI:** `{comp.psi:.1f}/100`")

        # 5. EXPLANATION
        st.markdown("---")
        st.subheader("5. SCIENTIFIC EXPLANATION")
        if "Predictable Mutation" in comp.our_classification:
            st.warning(f"**Vulnerability Finding**: {comp.explanation}")
        else:
            st.success(f"**Security Finding**: {comp.explanation}")

# TAB 2: THREE-PASSWORD BENCHMARK COMPARISON (Task 7)
with main_tabs[1]:
    st.header("⚖️ Three-Password Benchmark Comparison")
    st.markdown(
        "Direct comparison of the three canonical benchmark cases: "
        "**Password A** (predictable suffix), **Password B** (random control), and **Password C** (complex combination)."
    )

    benchmark_comps = compare_benchmark_passwords(weights=weights, h_ref=h_ref)
    df_benchmark = build_comparison_dataframe(benchmark_comps)

    st.dataframe(df_benchmark, width="stretch", hide_index=True)

    st.markdown("### Detailed Case-by-Case Breakdown")
    c_a, c_b, c_c = st.columns(3)

    with c_a:
        st.subheader("Password A: `Password123!`")
        st.markdown(
            "- **Pattern**: Dictionary base (`password`) + Capitalization (`P`) + Numeric Suffix (`123`) + Symbol (`!`)\n"
            "- **Conventional Meter**: 100/100 (Full marks for length 12 & all 4 classes)\n"
            "- **Theoretical Entropy**: 78.66 bits (looks very secure)\n"
            "- **Proposed MVS**: 80.0/100\n"
            "- **Proposed PSI**: 19.7/100 (**High Predictability Risk**)\n"
            "- **Existing Estimator (zxcvbn)**: 1/4 (Weak, ~4 seconds crack time)\n"
            "- **Takeaway**: Conventional entropy severely overestimates strength; PSI catches the predictable suffix."
        )

    with c_b:
        st.subheader("Password B: `vQ7mK2xR9zP4`")
        st.markdown(
            "- **Pattern**: Pure synthetic random-like sequence\n"
            "- **Conventional Meter**: 81.2/100\n"
            "- **Theoretical Entropy**: 71.45 bits\n"
            "- **Proposed MVS**: 0.0/100 (No penalty for generic numbers/letters)\n"
            "- **Proposed PSI**: 89.3/100 (Calibrated PSI: 100.0/100 — **Higher Security**)\n"
            "- **Existing Estimator (zxcvbn)**: 4/4 (Strong, ~3 years crack time)\n"
            "- **Takeaway**: Random character diversity is safely preserved without false-positive mutation penalties."
        )

    with c_c:
        st.subheader("Password C: `P@ssword2026!`")
        st.markdown(
            "- **Pattern**: Complex multi-layer mutation: TitleCase (`P`) + Leetspeak (`@`) + Year Suffix (`2026`) + Symbol (`!`)\n"
            "- **Conventional Meter**: 100/100\n"
            "- **Theoretical Entropy**: 85.21 bits\n"
            "- **Proposed MVS**: 100.0/100 (All 4 mutation patterns active)\n"
            "- **Proposed PSI**: 0.0/100 (Empirical PSI: 65.1/100 — **Vulnerable Family**)\n"
            "- **Existing Estimator (zxcvbn)**: 2/4 (Fair, ~17 minutes crack time)\n"
            "- **Takeaway**: Despite heavy leetspeak and symbols, all layers are dictionary-dependent mutations."
        )

# TAB 3: PHASE 3 EMPIRICAL PROBABILITIES & SURPRISAL
with main_tabs[2]:
    st.header("📊 Phase 3 Empirical Frequency & Information Content (Surprisal)")
    st.markdown(
        "Empirical probabilities $\\hat{p}_i = \\frac{k_i + 1}{n + 2}$ derived from the "
        "controlled synthetic corpus, and information content $I_i = -\\log_2(\\hat{p}_i)$ in bits."
    )

    sample_analysis = analyze_password(default_input, weights=weights, h_ref=h_ref)
    table_rows = []
    for component, score in sample_analysis.mutation_components.items():
        prob = sample_analysis.empirical_probabilities.get(component, 0.0)
        surp = sample_analysis.surprisal_bits.get(component, 0.0)
        w = weights.get(component, 0.0)
        table_rows.append({
            "Mutation Component": component.replace("_", " ").title(),
            "Active State (x_i)": f"{score:.2f}",
            "Laplace Smoothed Frequency (p̂_i)": f"{prob:.4f}",
            "Surprisal / Info Content (I_i)": f"{surp:.2f} bits",
            "Assigned Weight (w_i)": f"{w:.2f}",
            "Weighted Probability Contribution": f"{(w * prob * score):.4f}",
        })

    df_empirical = pd.DataFrame(table_rows)
    st.dataframe(df_empirical, width="stretch", hide_index=True)

    st.markdown(
        """
        - **Low Surprisal ($\approx 1.22$ bits)**: Capitalization and character substitution occur frequently in predictable passwords.
        - **Higher Surprisal ($\approx 1.79$ bits)**: Trailing symbols occur less frequently than plain numbers alone.
        - **Formula**:
        $$\\text{MVS}_{\\text{emp}} = 100 \\times \\frac{\\sum w_i \\hat{p}_i x_i}{\\sum w_i x_i}$$
        """
    )

# TAB 4: PUBLICATION VISUALIZATIONS
with main_tabs[3]:
    st.header("📈 Publication-Quality Visualizations")
    st.markdown("Visual figures generated from the benchmark comparison experiment on the research corpus:")

    results_dir = Path("results")
    chart_files = [
        ("baseline_roc_curves.png", "Receiver Operating Characteristic (ROC) Curves"),
        ("baseline_pr_curves.png", "Precision-Recall (PR) Curves"),
        ("baseline_confusion_matrix.png", "Confusion Matrix Comparison"),
        ("baseline_entropy_vs_psi.png", "Theoretical Entropy vs. Proposed PSI"),
        ("baseline_zxcvbn_vs_psi.png", "Dropbox zxcvbn Score vs. Proposed PSI"),
        ("baseline_mvs_vs_psi.png", "Mutation Vulnerability Score vs. Proposed PSI"),
        ("baseline_mutation_family_comparison.png", "Distribution of PSI Across Mutation Families"),
        ("baseline_conventional_vs_psi.png", "Conventional Password Meter Score vs. Proposed PSI"),
    ]

    selected_chart = st.selectbox("Select a visualization to inspect:", [title for _, title in chart_files])
    selected_filename = next(fname for fname, title in chart_files if title == selected_chart)
    chart_path = results_dir / selected_filename

    if chart_path.exists():
        st.image(str(chart_path), caption=selected_chart)
    else:
        st.warning(f"Chart file `{selected_filename}` not found. Run `python experiments.py` to generate it.")

# TAB 5: PUBLIC RESEARCH DATASET PIPELINE (Task 3)
with main_tabs[4]:
    st.header("📁 Public & Research Dataset Pipeline")
    st.markdown(
        "Import public password research datasets (e.g. from academic breach studies) "
        "and calculate privacy-preserving aggregate telemetry **without exposing sensitive credentials**."
    )

    st.info(
        "🔒 **Privacy Guarantee**: Individual plain-text passwords are never shown or logged. "
        "The engine only computes population-level mutation frequencies and distributions."
    )

    example_csv_path = Path("data/public_research_dataset_example.csv")
    if not example_csv_path.exists():
        create_example_public_research_dataset(example_csv_path)

    uploaded_file = st.file_uploader(
        "Upload a Research Dataset CSV (schema: `password_or_pattern`, `source_group`, `label`)",
        type=["csv"],
    )

    if uploaded_file is not None:
        # Save uploaded file temporarily for pipeline parsing
        temp_path = Path("data/uploaded_research_dataset.csv")
        with open(temp_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        target_dataset_path = temp_path
        st.success(f"Processing uploaded dataset `{uploaded_file.name}`...")
    else:
        target_dataset_path = example_csv_path
        st.caption("Displaying aggregate statistics for built-in research example dataset:")

    try:
        report = import_research_dataset(target_dataset_path)
        st.dataframe(report.summary_table(), width="stretch", hide_index=True)

        st.subheader("Zxcvbn Score Distribution in Research Corpus")
        dist_df = pd.DataFrame(
            list(report.zxcvbn_score_distribution.items()),
            columns=["zxcvbn Score (0=Weak, 4=Strong)", "Count"],
        )
        st.bar_chart(dist_df.set_index("zxcvbn Score (0=Weak, 4=Strong)"))

    except Exception as e:
        st.error(f"Error processing research dataset: {e}")

# TAB 6: MATHEMATICAL MODEL DETAILS
with main_tabs[5]:
    st.header("📐 Mathematical Model Formulations")
    st.markdown("Mathematical definitions implemented across Phase 1 to Phase 5:")

    st.latex(r"S = N^L \quad \text{where } L = \text{length}, N = \text{character pool size}")
    st.latex(r"H = L \cdot \log_2(N) \quad \text{(Shannon entropy under uniform independence)}")
    st.latex(r"\hat{p}_i = \frac{k_i + 1}{n + 2} \quad \text{(Laplace smoothed empirical frequency)}")
    st.latex(r"I_i = -\log_2(\hat{p}_i) \quad \text{(Information content / surprisal in bits)}")
    st.latex(r"\text{MVS} = 100 \sum w_i x_i \quad \text{and} \quad \text{MVS}_{\text{emp}} = 100 \frac{\sum w_i \hat{p}_i x_i}{\sum w_i x_i}")
    st.latex(r"\text{PSI} = 100 \times \min\left(\frac{H}{H_{\text{ref}}}, 1\right) \times \left(1 - \frac{\text{MVS}}{100}\right)")
    st.latex(r"\text{Decision Boundary: } \text{Classified Vulnerable if } \text{PSI}_{\text{cal}} < 69.0 \text{ at } H_{\text{ref}} = 50.0")
