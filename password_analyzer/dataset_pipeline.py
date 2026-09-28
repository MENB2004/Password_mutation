import csv
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import pandas as pd

from .core import analyze_password, character_set_size, entropy
from .baseline_comparator import get_existing_estimator_assessment


@dataclass
class DatasetAggregateReport:
    """Privacy-preserving aggregate metrics computed from a password dataset.

    Individual raw passwords are never displayed or stored in public reports.
    """
    dataset_name: str
    dataset_type: str  # 'SYNTHETIC DATA' or 'REAL/PUBLIC RESEARCH DATA'
    total_records: int
    dictionary_base_frequency: float
    mutation_frequency: float
    capitalization_frequency: float
    substitution_frequency: float
    numeric_suffix_frequency: float
    symbol_suffix_frequency: float
    mean_length: float
    mean_entropy: float
    mean_mvs: float
    mean_empirical_mvs: float
    mean_psi: float
    mean_empirical_psi: float
    zxcvbn_score_distribution: Dict[int, int]
    source_distribution: Dict[str, int]
    privacy_notice: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def summary_table(self) -> pd.DataFrame:
        data = [
            ("Dataset Name", self.dataset_name),
            ("Dataset Type", self.dataset_type),
            ("Total Records Analyzed", f"{self.total_records:,}"),
            ("Dictionary Base Prevalence", f"{self.dictionary_base_frequency * 100:.2f}%"),
            ("Any Mutation Prevalence", f"{self.mutation_frequency * 100:.2f}%"),
            ("  - Capitalization Rate", f"{self.capitalization_frequency * 100:.2f}%"),
            ("  - Leetspeak Substitution Rate", f"{self.substitution_frequency * 100:.2f}%"),
            ("  - Numeric Suffix Rate", f"{self.numeric_suffix_frequency * 100:.2f}%"),
            ("  - Symbol Suffix Rate", f"{self.symbol_suffix_frequency * 100:.2f}%"),
            ("Mean Password Length", f"{self.mean_length:.2f}"),
            ("Mean Theoretical Entropy", f"{self.mean_entropy:.2f} bits"),
            ("Mean Baseline MVS", f"{self.mean_mvs:.2f}/100"),
            ("Mean Empirical MVS", f"{self.mean_empirical_mvs:.2f}/100"),
            ("Mean Baseline PSI", f"{self.mean_psi:.2f}/100"),
            ("Mean Empirical PSI", f"{self.mean_empirical_psi:.2f}/100"),
        ]
        return pd.DataFrame(data, columns=["Metric", "Value"])


def import_research_dataset(file_path: Union[str, Path],
                            dataset_type: str = "REAL/PUBLIC RESEARCH DATA",
                            dataset_name: Optional[str] = None) -> DatasetAggregateReport:
    """Import and analyze an external or public research password dataset.

    Expected CSV schema (flexible):
      - 'password' OR 'password_or_pattern'
      - optional: 'source', 'source_group', 'group'
      - optional: 'label', 'category'

    PRIVACY & ETHICAL GUARANTEE:
      Individual raw passwords are NOT printed, logged, or exposed.
      Only aggregate population distributions are returned.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Dataset file not found: {file_path}")

    d_name = dataset_name or path.stem

    total = 0
    dict_count = 0
    mut_count = 0
    cap_count = 0
    sub_count = 0
    num_count = 0
    sym_count = 0

    lengths: List[int] = []
    entropies: List[float] = []
    mvs_list: List[float] = []
    emp_mvs_list: List[float] = []
    psi_list: List[float] = []
    emp_psi_list: List[float] = []
    zxcvbn_dist: Dict[int, int] = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0}
    source_dist: Dict[str, int] = {}

    with open(path, mode="r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise ValueError("CSV file is empty or missing headers.")

        # Resolve field names flexibly
        pw_field = next(
            (c for c in reader.fieldnames if c.lower() in ["password", "password_or_pattern", "pwd", "text"]),
            None
        )
        if not pw_field:
            raise ValueError(
                f"Missing required password column. Expected one of: 'password', 'password_or_pattern'. Found: {reader.fieldnames}"
            )

        src_field = next(
            (c for c in reader.fieldnames if c.lower() in ["source", "source_group", "source/group", "group"]),
            None
        )

        for row in reader:
            raw_pw = row.get(pw_field, "").strip()
            if not raw_pw:
                continue

            total += 1
            src = row.get(src_field, "unspecified") if src_field else "unspecified"
            source_dist[src] = source_dist.get(src, 0) + 1

            # Perform internal analysis (in-memory, never persisted to logs/UI)
            analysis = analyze_password(raw_pw)
            est = get_existing_estimator_assessment(raw_pw)

            lengths.append(analysis.password_length)
            entropies.append(analysis.entropy_bits)
            mvs_list.append(analysis.mvs)
            emp_mvs_list.append(analysis.empirical_mvs)
            psi_list.append(analysis.psi)
            emp_psi_list.append(analysis.empirical_psi)

            z_score = est["score"]
            zxcvbn_dist[z_score] = zxcvbn_dist.get(z_score, 0) + 1

            if analysis.dictionary_base:
                dict_count += 1
            if analysis.mutations:
                mut_count += 1
            if "capitalization" in analysis.mutations:
                cap_count += 1
            if "character substitution" in analysis.mutations:
                sub_count += 1
            if "numeric suffix" in analysis.mutations:
                num_count += 1
            if "symbol suffix" in analysis.mutations:
                sym_count += 1

    if total == 0:
        raise ValueError("No valid password records were found in the dataset.")

    return DatasetAggregateReport(
        dataset_name=d_name,
        dataset_type=dataset_type,
        total_records=total,
        dictionary_base_frequency=dict_count / total,
        mutation_frequency=mut_count / total,
        capitalization_frequency=cap_count / total,
        substitution_frequency=sub_count / total,
        numeric_suffix_frequency=num_count / total,
        symbol_suffix_frequency=sym_count / total,
        mean_length=sum(lengths) / total,
        mean_entropy=sum(entropies) / total,
        mean_mvs=sum(mvs_list) / total,
        mean_empirical_mvs=sum(emp_mvs_list) / total,
        mean_psi=sum(psi_list) / total,
        mean_empirical_psi=sum(emp_psi_list) / total,
        zxcvbn_score_distribution=zxcvbn_dist,
        source_distribution=source_dist,
        privacy_notice=(
            "CONFIDENTIALITY GUARANTEE: Individual raw passwords are not exposed. "
            "All telemetry represents population aggregate statistics."
        ),
    )


def create_example_public_research_dataset(target_path: Union[str, Path]) -> Path:
    """Create a documented, safe sample public research dataset file following

    the research schema (password_or_pattern, source_group, label).
    """
    path = Path(target_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    records = [
        # Common pattern archetypes based on published academic password breach analyses
        ("password2024", "public_leak_sample_A", "dictionary_year_suffix"),
        ("Admin@123", "public_leak_sample_A", "title_case_symbol_number"),
        ("Welcome#1", "public_leak_sample_A", "title_case_symbol_number"),
        ("summer2025!", "public_leak_sample_B", "dictionary_year_symbol"),
        ("Security@2026", "public_leak_sample_B", "title_case_symbol_year"),
        ("college99", "public_leak_sample_B", "dictionary_num_suffix"),
        ("p@ssw0rd123", "public_leak_sample_C", "leetspeak_number_suffix"),
        ("qwerty2024", "public_leak_sample_C", "walk_year_suffix"),
        ("football!", "public_leak_sample_C", "dictionary_symbol_suffix"),
        ("dr@g0n2025", "public_leak_sample_D", "leetspeak_year_suffix"),
        ("Winter2026!", "public_leak_sample_D", "title_case_year_symbol"),
        ("master2024#", "public_leak_sample_D", "dictionary_year_symbol"),
        ("K8#mP2$xQ9vL5", "curated_random_controls", "high_entropy_control"),
        ("tR4*wY9!zC1&bV", "curated_random_controls", "high_entropy_control"),
        ("pL9@vM3#xZ7$qK", "curated_random_controls", "high_entropy_control"),
    ]

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["password_or_pattern", "source_group", "label"])
        writer.writerows(records)

    return path
