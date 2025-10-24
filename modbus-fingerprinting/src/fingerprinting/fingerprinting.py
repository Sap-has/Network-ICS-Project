import numpy as np
import pandas as pd
import os
import json


def _select_features(df: pd.DataFrame, features: list = None) -> list:
    # Exclude obvious non-feature columns
    exclude = {'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'function_name'}
    if features is not None:
        return features
    # pick numeric dtype columns except excluded
    picks = [c for c in df.columns if c not in exclude and pd.api.types.is_numeric_dtype(df[c])]
    return picks


def _compute_freq_dist(series: pd.Series, bins: int = 10, top_n: int = 10) -> dict:
    # Drop NA
    s = series.dropna()
    if s.empty:
        return {'type': 'empty', 'dist': {}}

    unique_vals = s.unique()
    # If many unique values and numeric, return histogram
    if pd.api.types.is_numeric_dtype(s) and len(unique_vals) > max(top_n, bins):
        counts, bin_edges = np.histogram(s, bins=bins)
        return {
            'type': 'hist',
            'bins': bin_edges.tolist(),
            'counts': counts.tolist(),
            'total': int(s.size)
        }

    # Otherwise return normalized value_counts (categorical / small-unique)
    vc = s.value_counts(normalize=True)
    # limit to top_n
    vc = vc.iloc[:top_n]
    return {
        'type': 'value_counts',
        'dist': vc.to_dict(),
        'total': int(s.size)
    }
def group_and_compute_stats(df, group_cols=('src_ip', 'dst_ip', 'unit_id'), features=None, thresholds=None, bins=10, top_n=10):
    """Group `df` by `group_cols` and compute statistics per numeric feature.

    Returns:
        - summary_df: DataFrame indexed by group with flattened columns like
        '<feature>_mean', '<feature>_std', '<feature>_count',
        '<feature>_count_below_threshold', '<feature>_count_above_threshold'
        - freq_dists: nested dict mapping group_tuple, feature, then distribution info

    Parameters:
        df: input dataframe (output of feature extractor)
        group_cols: tuple of 3 column names to group by
        features: list of feature column names to analyze (defaults to numeric picks)
        thresholds: dict(feature->value) or scalar value used to count below/above.
                    If None, uses the global median per feature.
        bins: number of bins to use for numeric histograms
        top_n: when returning value_counts limit to top_n entries
    """
    # Basic validations
    if df is None or df.empty:
        # Return empty results
        empty_df = pd.DataFrame()
        return empty_df, {}

    for col in group_cols:
        if col not in df.columns:
            raise ValueError(f"Grouping column '{col}' not found in dataframe")

    features = _select_features(df, features)
    if not features:
        # nothing to do
        return pd.DataFrame(), {}

    # Determine thresholds per feature
    if thresholds is None:
        # use global median per feature
        thresholds_map = {f: float(df[f].median()) for f in features}
    elif isinstance(thresholds, dict):
        thresholds_map = {f: thresholds.get(f, float(df[f].median())) for f in features}
    else:
        # scalar applied to all
        thresholds_map = {f: float(thresholds) for f in features}

    grouped = df.groupby(list(group_cols))

    # Compute basic aggregates
    agg_funcs = {f: ['mean', 'std', 'count'] for f in features}
    agg_df = grouped.agg(agg_funcs)
    # Flatten MultiIndex columns
    agg_df.columns = [f'{col[0]}_{col[1]}' for col in agg_df.columns]

    # Compute counts below/above thresholds
    def _count_comp(s: pd.Series, thr: float, comp: str) -> int:
        if comp == 'below':
            return int(s.dropna().lt(thr).sum())
        return int(s.dropna().gt(thr).sum())

    # Prepare containers for frequency distributions
    freq_dists = {}

    # For each group, compute the counts and distributions
    for name, group in grouped:
        # name is a tuple of group values
        freq_dists[name] = {}
        for f in features:
            thr = thresholds_map.get(f, float(df[f].median()))
            below = _count_comp(group[f], thr, 'below')
            above = _count_comp(group[f], thr, 'above')
            # store in agg_df later: we'll augment agg_df with these columns
            col_below = f + '_count_below_threshold'
            col_above = f + '_count_above_threshold'

            # ensure columns exist in agg_df
            # set values via .at
            try:
                agg_df.at[name, col_below] = below
                agg_df.at[name, col_above] = above
            except Exception:
                # if agg_df index is not matching types, try to set via loc
                agg_df.loc[name, col_below] = below
                agg_df.loc[name, col_above] = above

            # frequency distribution
            freq_info = _compute_freq_dist(group[f], bins=bins, top_n=top_n)
            freq_dists[name][f] = {
                'threshold': thr,
                'count_below': below,
                'count_above': above,
                'freq': freq_info,
            }

    # Fill NA with zeros for anything missing
    agg_df = agg_df.fillna(0)

    # Convert index to columns for easier consumption
    agg_df = agg_df.reset_index()
    # Export to CSV, try to do it to folder
    csv_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'csv_outputs')
    os.makedirs(csv_dir, exist_ok=True)
    
    # Export summary stats
    csv_path = os.path.join(csv_dir, 'fingerprint_summary.csv')
    agg_df.to_csv(csv_path, index=False)
    print('csv')
    
    # Export frequency distributions
    json_path = os.path.join(csv_dir, 'freq_distributions.json')
    with open(json_path, 'w') as f:
        json.dump(freq_dists, f, indent=2)
    print('json')

    return agg_df, freq_dists
