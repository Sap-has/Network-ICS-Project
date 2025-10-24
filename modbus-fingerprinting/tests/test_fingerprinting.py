import unittest
import pandas as pd
from src.fingerprinting.fingerprinting import group_and_compute_stats


class TestFingerprintingStats(unittest.TestCase):

    def test_group_stats_and_freqs(self):
        # build a small dataframe with two groups
        data = [
            {'src_ip': '1.1.1.1', 'dst_ip': '2.2.2.2', 'unit_id': 1, 'f1': 1.0, 'f2': 10.0},
            {'src_ip': '1.1.1.1', 'dst_ip': '2.2.2.2', 'unit_id': 1, 'f1': 2.0, 'f2': 20.0},
            {'src_ip': '1.1.1.1', 'dst_ip': '2.2.2.2', 'unit_id': 1, 'f1': 3.0, 'f2': 30.0},
            {'src_ip': '9.9.9.9', 'dst_ip': '8.8.8.8', 'unit_id': 2, 'f1': 5.0, 'f2': 7.0},
            {'src_ip': '9.9.9.9', 'dst_ip': '8.8.8.8', 'unit_id': 2, 'f1': 6.0, 'f2': 8.0},
        ]

        df = pd.DataFrame(data)

        # provide explicit thresholds so results are deterministic
        thresholds = {'f1': 3.0, 'f2': 15.0}

        summary_df, freq_dists = group_and_compute_stats(df, features=['f1', 'f2'], thresholds=thresholds)

        # There should be two groups
        self.assertEqual(len(summary_df), 2)

        # Check expected aggregated columns exist
        expected_cols = ['f1_mean', 'f1_std', 'f1_count', 'f1_count_below_threshold', 'f1_count_above_threshold',
                         'f2_mean', 'f2_std', 'f2_count', 'f2_count_below_threshold', 'f2_count_above_threshold']
        for c in expected_cols:
            self.assertIn(c, summary_df.columns)

        # Find group row for first group
        row1 = summary_df[(summary_df['src_ip'] == '1.1.1.1') & (summary_df['dst_ip'] == '2.2.2.2') & (summary_df['unit_id'] == 1)]
        self.assertEqual(int(row1['f1_count'].iloc[0]), 3)
        # With threshold 3.0, values <3.0 are 1.0 and 2.0 -> 2 values; >3.0 none (3.0 is not >)
        self.assertEqual(int(row1['f1_count_below_threshold'].iloc[0]), 2)
        self.assertEqual(int(row1['f1_count_above_threshold'].iloc[0]), 0)

        # For f2 threshold 15, below are 10 only (1), above are 20 and 30 (2)
        self.assertEqual(int(row1['f2_count_below_threshold'].iloc[0]), 1)
        self.assertEqual(int(row1['f2_count_above_threshold'].iloc[0]), 2)

        # Frequency dict present for that group
        group_key = ('1.1.1.1', '2.2.2.2', 1)
        self.assertIn(group_key, freq_dists)
        self.assertIn('f1', freq_dists[group_key])
        self.assertIn('f2', freq_dists[group_key])


if __name__ == '__main__':
    unittest.main()
