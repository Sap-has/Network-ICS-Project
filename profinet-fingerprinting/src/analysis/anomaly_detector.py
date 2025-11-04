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

    # Initialize new columns in agg_df for thresholds
    threshold_data = {}
    freq_dists_serializable = {}

    # For each group, compute the counts and distributions
    for name, group in grouped:
        # Convert tuple name to string for JSON serialization
        name_str = '_'.join(str(x) for x in name)
        freq_dists_serializable[name_str] = {}
        
        for f in features:
            thr = thresholds_map.get(f, float(df[f].median()))
            below = _count_comp(group[f], thr, 'below')
            above = _count_comp(group[f], thr, 'above')
            
            # Store threshold data for batch update
            if name not in threshold_data:
                threshold_data[name] = {}
            threshold_data[name][f + '_count_below_threshold'] = below
            threshold_data[name][f + '_count_above_threshold'] = above

            # frequency distribution
            freq_info = _compute_freq_dist(group[f], bins=bins, top_n=top_n)
            freq_dists_serializable[name_str][f] = {
                'threshold': thr,
                'count_below': below,
                'count_above': above,
                'freq': freq_info,
            }
    
    # Batch update the DataFrame with threshold data
    threshold_df = pd.DataFrame.from_dict(threshold_data, orient='index')
    if not threshold_df.empty:
        # Make sure the threshold_df index matches the MultiIndex of agg_df
        try:
            threshold_df.index = pd.MultiIndex.from_tuples(threshold_df.index, names=list(group_cols))
        except Exception:
            # if conversion fails, leave as-is and rely on concat alignment
            pass

        # Concatenate once to avoid repeated column insertions (prevents fragmentation)
        agg_df = pd.concat([agg_df, threshold_df], axis=1)
        # Make a contiguous copy to fully defragment
        agg_df = agg_df.copy()
            
    # Replace freq_dists with the serializable version
    freq_dists = freq_dists_serializable

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