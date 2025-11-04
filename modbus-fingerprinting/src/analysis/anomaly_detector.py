import numpy as np
import pandas as pd
import os
import json
from typing import List, Dict

# --- Helper Functions from original file (kept for compatibility) ---

def _select_features(df: pd.DataFrame, features: list = None) -> list:
    # Exclude obvious non-feature columns
    exclude = {'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'function_name'}
    if features is not None:
        return features
    # pick numeric dtype columns except excluded
    picks = [c for c in df.columns if c not in exclude and pd.api.types.is_numeric_dtype(df[c])]
    return picks


def _compute_freq_dist(series: pd.Series, bins: int = 10, top_n: int = 10) -> dict:
    s = series.dropna()
    if s.empty:
        return {'type': 'empty', 'dist': {}}

    unique_vals = s.unique()
    if pd.api.types.is_numeric_dtype(s) and len(unique_vals) > max(top_n, bins):
        counts, bin_edges = np.histogram(s, bins=bins)
        return {
            'type': 'hist',
            'bins': bin_edges.tolist(),
            'counts': counts.tolist(),
            'total': int(s.size)
        }

    vc = s.value_counts(normalize=True)
    vc = vc.iloc[:top_n]
    return {
        'type': 'value_counts',
        'dist': vc.to_dict(),
        'total': int(s.size)
    }

def group_and_compute_stats(df, group_cols=('src_ip', 'dst_ip', 'unit_id'), features=None, thresholds=None, bins=10, top_n=10):
    # This function is kept for backward compatibility and is not the main anomaly detection logic
    # The implementation details remain the same as in the original file.
    
    # Basic validations
    if df is None or df.empty:
        empty_df = pd.DataFrame()
        return empty_df, {}

    for col in group_cols:
        if col not in df.columns:
            raise ValueError(f"Grouping column '{col}' not found in dataframe")

    features = _select_features(df, features)
    if not features:
        return pd.DataFrame(), {}

    # Determine thresholds per feature
    if thresholds is None:
        thresholds_map = {f: float(df[f].median()) for f in features}
    elif isinstance(thresholds, dict):
        thresholds_map = {f: thresholds.get(f, float(df[f].median())) for f in features}
    else:
        thresholds_map = {f: float(thresholds) for f in features}

    grouped = df.groupby(list(group_cols))

    # Compute basic aggregates
    agg_funcs = {f: ['mean', 'std', 'count'] for f in features}
    agg_df = grouped.agg(agg_funcs)
    agg_df.columns = [f'{col[0]}_{col[1]}' for col in agg_df.columns]

    # Compute counts below/above thresholds (simplified, full details omitted for brevity here)
    def _count_comp(s: pd.Series, thr: float, comp: str) -> int:
        if comp == 'below':
            return int(s.dropna().lt(thr).sum())
        return int(s.dropna().gt(thr).sum())

    freq_dists = {}
    threshold_data = {}
    freq_dists_serializable = {}

    for name, group in grouped:
        name_str = '_'.join(str(x) for x in name)
        freq_dists_serializable[name_str] = {}
        
        for f in features:
            thr = thresholds_map.get(f, float(df[f].median()))
            below = _count_comp(group[f], thr, 'below')
            above = _count_comp(group[f], thr, 'above')
            
            if name not in threshold_data:
                threshold_data[name] = {}
            threshold_data[name][f + '_count_below_threshold'] = below
            threshold_data[name][f + '_count_above_threshold'] = above

            freq_info = _compute_freq_dist(group[f], bins=bins, top_n=top_n)
            freq_dists_serializable[name_str][f] = {
                'threshold': thr,
                'count_below': below,
                'count_above': above,
                'freq': freq_info,
            }
    
    threshold_df = pd.DataFrame.from_dict(threshold_data, orient='index')
    if not threshold_df.empty:
        try:
            threshold_df.index = pd.MultiIndex.from_tuples(threshold_df.index, names=list(group_cols))
        except Exception:
            pass

        agg_df = pd.concat([agg_df, threshold_df], axis=1).copy()
            
    freq_dists = freq_dists_serializable
    agg_df = agg_df.fillna(0)
    agg_df = agg_df.reset_index()
    
    # Export to CSV and JSON (kept for compatibility)
    csv_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'csv_outputs')
    os.makedirs(csv_dir, exist_ok=True)
    
    csv_path = os.path.join(csv_dir, 'fingerprint_summary.csv')
    agg_df.to_csv(csv_path, index=False)
    
    json_path = os.path.join(csv_dir, 'freq_distributions.json')
    with open(json_path, 'w') as f:
        json.dump(freq_dists, f, indent=2)

    return agg_df, freq_dists

# --- New Anomaly Detector Logic ---

class ModbusAnomalyDetector:
    """
    Detects anomalies in Modbus traffic based on BASELINE_CRITERIA.md.
    This detector flags individual packets that violate defined statistical and protocol rules.
    """
    
    # Baseline values from BASELINE_CRITERIA.md (Normal Traffic Characteristics)
    BASELINE = {
        'packet_length_mean': 180,  # Midpoint of 60-300 bytes
        'packet_length_std': 30,    # Midpoint of 10-50 bytes
        'iat_mean': 500,            # Midpoint of 10-1000ms
        'iat_cv': 0.5,              # Max CV
        'payload_entropy_min': 3.5,
        'payload_entropy_max': 6.5,
    }
    
    # Anomaly Indicators from BASELINE_CRITERIA.md
    ANOMALY_THRESHOLDS = {
        # Statistical Anomalies (using a simple 2*std approach relative to an assumed baseline)
        'packet_size_outlier': 2, # > 2*std
        'iat_outlier': 2,         # > 2*std
        'entropy_low': 2.0,       # < 2.0 bits (lower bound for strong anomaly)
        'entropy_high': 7.0,      # > 7.0 bits (upper bound for strong anomaly)
        'iat_burst_ms': 1.0,      # IAT drops below 1ms
        'iat_burst_count': 10,    # For > 10 consecutive packets
        
        # Protocol/Pattern Anomalies
        'invalid_protocol_id': 0,
        'invalid_unit_id_min': 1,
        'invalid_unit_id_max': 247,
        'max_unique_fc_scan': 10,  # > 10 unique function codes
        'rapid_fc_change_percent': 0.5, # > 50% sequential changes
        'reserved_fc_min': 7,
        'reserved_fc_max': 14,
        # Other reserved codes (17-19, 24-127) are covered by general FC validity check if not in MODBUS_FUNCTION_CODES
    }

    def __init__(self, features_df: pd.DataFrame):
        self.df = features_df.copy()
        
        # Compute global baseline statistics from the input data (for 2-sigma checks)
        self.global_stats = {
            'packet_length_mean': self.df['packet_length'].mean(),
            'packet_length_std': self.df['packet_length'].std(),
            'time_delta_mean': self.df['time_delta_ms'].mean(),
            'time_delta_std': self.df['time_delta_ms'].std(),
            'payload_entropy_mean': self.df['payload_entropy'].mean(),
            'payload_entropy_std': self.df['payload_entropy'].std(),
            'unique_function_codes_count': self.df['function_code'].nunique()
        }

    def _check_statistical_anomalies(self) -> pd.Series:
        """Flags packets that are statistical outliers based on 2-sigma rule."""
        is_anomaly = pd.Series(False, index=self.df.index)
        
        # 1. Packet Size Anomaly (> 2σ from baseline mean)
        mean_len = self.global_stats.get('packet_length_mean', self.BASELINE['packet_length_mean'])
        std_len = self.global_stats.get('packet_length_std', self.BASELINE['packet_length_std'])
        upper_bound_len = mean_len + self.ANOMALY_THRESHOLDS['packet_size_outlier'] * std_len
        lower_bound_len = mean_len - self.ANOMALY_THRESHOLDS['packet_size_outlier'] * std_len
        is_anomaly |= (self.df['packet_length'] > upper_bound_len) | (self.df['packet_length'] < lower_bound_len)
        
        # 2. IAT Anomaly (> 2σ from baseline mean)
        # Note: Using rolling window stats might be better, but for simplicity, we use global here
        mean_iat = self.global_stats.get('time_delta_mean', self.BASELINE['iat_mean'])
        std_iat = self.global_stats.get('time_delta_std', 0)
        upper_bound_iat = (mean_iat + self.ANOMALY_THRESHOLDS['iat_outlier'] * std_iat)
        # Assuming IAT can't be negative, lower bound is usually near 0 for polling traffic
        lower_bound_iat = max(0.0, mean_iat - self.ANOMALY_THRESHOLDS['iat_outlier'] * std_iat)
        is_anomaly |= (self.df['time_delta_ms'] > upper_bound_iat) | (self.df['time_delta_ms'] < lower_bound_iat)
        
        # 3. Entropy Anomaly (< 2.0 or > 7.0 bits)
        is_anomaly |= (self.df['payload_entropy'] < self.ANOMALY_THRESHOLDS['entropy_low'])
        is_anomaly |= (self.df['payload_entropy'] > self.ANOMALY_THRESHOLDS['entropy_high'])
        
        return is_anomaly.rename('statistical_anomaly')

    def _check_protocol_violations(self) -> pd.Series:
        """Flags packets that violate Modbus protocol compliance."""
        
        # The feature extractor already computed these!
        # 1. Invalid Protocol ID (protocol_id_valid == 0)
        # 2. Invalid Unit ID (unit_id_valid == 0)
        # 3. Length Mismatch (length_consistent == 0)
        # 4. Malformed/Reserved FC (function_code_valid == 0 or FC in reserved range)
        
        is_anomaly = pd.Series(False, index=self.df.index)
        
        # Check pre-computed protocol validity features
        is_anomaly |= (self.df['protocol_id_valid'] == 0)
        is_anomaly |= (self.df['unit_id_valid'] == 0)
        is_anomaly |= (self.df['length_consistent'] == 0)
        
        # Check reserved function codes (7-14, 17-19, 24-127)
        reserved_fc_range1 = (self.df['function_code'] >= self.ANOMALY_THRESHOLDS['reserved_fc_min']) & \
                             (self.df['function_code'] <= self.ANOMALY_THRESHOLDS['reserved_fc_max'])
        
        # The function_code_valid feature already flags codes > 127
        # We need to explicitly check other reserved ranges not covered by MODBUS_FUNCTION_CODES
        
        # A simple check: if it's not a read/write/error, it's potentially reserved/unknown
        is_anomaly |= (self.df['is_read_operation'] == 0) & \
                      (self.df['is_write_operation'] == 0) & \
                      (self.df['is_error_response'] == 0) & \
                      (self.df['function_code'] >= 7) & \
                      (self.df['function_code'] <= 127)

        return is_anomaly.rename('protocol_violation')

    def _check_pattern_anomalies(self) -> pd.Series:
        """Flags packets involved in pattern anomalies (burst, scanning, rapid changes)."""
        is_anomaly = pd.Series(False, index=self.df.index)

        # 1. Burst Traffic: IAT drops below 1ms for > 10 consecutive packets
        # The 'burst_indicator' (IAT < 5ms) is close, but we use the strict 1ms rule and rolling sum
        burst_indicator = (self.df['time_delta_ms'] < self.ANOMALY_THRESHOLDS['iat_burst_ms']).astype(int)
        burst_streak = burst_indicator.rolling(window=self.ANOMALY_THRESHOLDS['iat_burst_count'], min_periods=1).sum()
        is_anomaly |= (burst_streak >= self.ANOMALY_THRESHOLDS['iat_burst_count'])
        
        # 2. Rapid Function Changes: > 50% sequential changes (using rolling 10-packet window)
        # function_code_stability_10 < 0.5 (which means > 50% changes)
        is_anomaly |= (self.df['function_code_stability_10'] < (1.0 - self.ANOMALY_THRESHOLDS['rapid_fc_change_percent']))

        # 3. Function Code Scanning (Overall traffic check, not per packet, but flagged on all if detected)
        if self.global_stats['unique_function_codes_count'] > self.ANOMALY_THRESHOLDS['max_unique_fc_scan']:
            # Flag all packets if the overall flow shows scanning behavior
            is_anomaly = pd.Series(True, index=self.df.index)
        
        return is_anomaly.rename('pattern_anomaly')
    
    def detect_anomalies(self) -> List[Dict]:
        """
        Runs all anomaly checks and returns a list of dictionaries for all
        packets flagged as anomalous.
        """
        
        if self.df.empty:
            return []
            
        # Run the checks
        stat_anom = self._check_statistical_anomalies()
        prot_viol = self._check_protocol_violations()
        patt_anom = self._check_pattern_anomalies()
        
        # Combine all flags
        self.df['is_anomaly'] = stat_anom | prot_viol | patt_anom
        
        # Filter for only anomalous packets
        anomalous_packets = self.df[self.df['is_anomaly']].copy()
        
        if anomalous_packets.empty:
            return []
            
        # Create a detailed report for each anomalous packet
        anomalies_report = []
        for index, row in anomalous_packets.iterrows():
            reasons = []
            
            if stat_anom[index]:
                reasons.append("Statistical Outlier (Packet Size, IAT, or Entropy)")
            if prot_viol[index]:
                reasons.append("Protocol Violation (Invalid Protocol ID, Unit ID, Length Mismatch, or Reserved FC)")
            if patt_anom[index]:
                if self.global_stats['unique_function_codes_count'] > self.ANOMALY_THRESHOLDS['max_unique_fc_scan']:
                    reasons.append("Pattern Anomaly: Function Code Scanning Detected in Flow")
                if row['function_code_stability_10'] < (1.0 - self.ANOMALY_THRESHOLDS['rapid_fc_change_percent']):
                    reasons.append("Pattern Anomaly: Rapid Function Code Change")
                # Check for burst indicator more carefully (using the exact IAT < 1ms logic)
                if (row['time_delta_ms'] < self.ANOMALY_THRESHOLDS['iat_burst_ms']) and row[patt_anom.name]:
                     reasons.append("Pattern Anomaly: Burst Traffic (IAT < 1ms)")
            
            anomalies_report.append({
                'index': index,
                'timestamp': row['timestamp'],
                'src_ip': row['src_ip'],
                'dst_ip': row['dst_ip'],
                'function_code': int(row['function_code']),
                'function_name': row['function_name'],
                'packet_length': int(row['packet_length']),
                'time_delta_ms': row['time_delta_ms'],
                'payload_entropy': row['payload_entropy'],
                'anomaly_reasons': list(set(reasons)) # Use set to de-duplicate reasons
            })
            
        return anomalies_report

# The original group_and_compute_stats is kept here for project continuity.
# The ModbusAnalysisTool in run_analysis.py should now use ModbusAnomalyDetector.