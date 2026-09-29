const GATED_METRICS: &[&str] = &[
    "unit/insn_locator",
    "unit/string_locator",
    "unit/code_scan",
    "unit/method_locator",
    "unit/field_locator",
    "unit/type_locator",
    "unit/method_ref_scan",
    "unit/field_ref_scan",
    "core/decompile",
    "cli_getclass/cli_getclass",
    "cli_findrefs/cli_findrefs",
];

#[derive(Debug)]
struct Comparison {
    statistically_significant: bool,
    material_slowdown: bool,
    regression: bool,
}

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    if values.len() % 2 == 0 {
        (values[middle - 1] + values[middle]) / 2.0
    } else {
        values[middle]
    }
}

fn combinations(n: usize, k: usize) -> u64 {
    let k = k.min(n - k);
    (0..k).fold(1_u64, |value, index| {
        value * (n - index) as u64 / (index + 1) as u64
    })
}

fn compare_pairs(
    base: &[f64],
    candidate: &[f64],
    metric_count: usize,
    alpha: f64,
    effect_floor_percent: f64,
) -> Result<Comparison, &'static str> {
    if base.len() != candidate.len() || base.len() < 15 {
        return Err("at least 15 complete paired samples are required");
    }
    if metric_count < 1 || !(0.0 < alpha && alpha < 1.0) || effect_floor_percent < 0.0 {
        return Err("invalid comparison parameters");
    }
    if base
        .iter()
        .chain(candidate)
        .any(|value| !value.is_finite() || *value <= 0.0)
    {
        return Err("timings must be finite and positive");
    }

    let mut ratios: Vec<f64> = base
        .iter()
        .zip(candidate)
        .map(|(old, new)| new / old)
        .collect();
    let slower = ratios.iter().filter(|&&value| value > 1.0).count();
    let faster = ratios.iter().filter(|&&value| value < 1.0).count();
    let n = slower + faster;
    let p_value =
        (slower..=n).map(|k| combinations(n, k)).sum::<u64>() as f64 / 2_f64.powi(n as i32);
    let threshold = alpha / metric_count as f64;
    let paired_median_change_percent = (median(&mut ratios) - 1.0) * 100.0;
    let statistically_significant = p_value < threshold;
    let material_slowdown = paired_median_change_percent >= effect_floor_percent;
    Ok(Comparison {
        statistically_significant,
        material_slowdown,
        regression: statistically_significant && material_slowdown,
    })
}

fn compare(base: &[f64], candidate: &[f64], metric_count: usize) -> Comparison {
    compare_pairs(base, candidate, metric_count, 0.05, 3.0).unwrap()
}

fn should_gate(metric: &str, result: &Comparison) -> bool {
    GATED_METRICS.contains(&metric) && result.regression
}

#[test]
fn consistent_small_regression_is_reported_but_not_gated() {
    let result = compare(&[100.0; 31], &[100.1; 31], 26);
    assert!(result.statistically_significant);
    assert!(!result.material_slowdown);
    assert!(!result.regression);
}

#[test]
fn consistent_large_regression_fails() {
    let result = compare(&[100.0; 31], &[200.0; 31], 26);
    assert!(result.statistically_significant);
    assert!(result.material_slowdown);
    assert!(result.regression);
}

#[test]
fn effect_floor_is_inclusive() {
    assert!(compare(&[100.0; 31], &[103.0; 31], 26).regression);
}

#[test]
fn only_aggregate_method_locator_is_gated() {
    let result = compare(&[100.0; 31], &[200.0; 31], 11);
    assert!(should_gate("unit/method_locator", &result));
    assert!(!should_gate("unit/method_locator_none_class", &result));
    assert!(!should_gate(
        "unit/method_locator_fuzzy_class_only",
        &result
    ));
}

#[test]
fn improvement_and_equal_times_pass() {
    for value in [50.0, 100.0] {
        assert!(!compare(&[100.0; 31], &[value; 31], 26).regression);
    }
}

#[test]
fn balanced_noise_does_not_fail() {
    let mut values = Vec::new();
    for _ in 0..15 {
        values.extend([90.0, 110.0]);
    }
    values.push(100.0);
    assert!(!compare(&[100.0; 31], &values, 26).regression);
}

#[test]
fn single_outlier_does_not_fail() {
    let mut values = vec![100.0; 30];
    values.push(10_000.0);
    assert!(!compare(&[100.0; 31], &values, 26).regression);
}

#[test]
fn missing_or_invalid_measurements_fail() {
    for values in [
        Vec::new(),
        vec![100.0; 30],
        vec![f64::NAN; 31],
        vec![0.0; 31],
    ] {
        assert!(compare_pairs(&[100.0; 31], &values, 26, 0.05, 3.0).is_err());
    }
}
