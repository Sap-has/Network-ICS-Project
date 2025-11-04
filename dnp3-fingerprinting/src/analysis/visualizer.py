import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from typing import *
import json

class ModbusAnalysisTool:
    def __init__(self, features_df: pd.DataFrame = None, summary_stats: Dict = None):
        self.df = features_df
        self.stats = summary_stats
        self.setup_plotting_style()

    def setup_plotting_style(self):
        plt.style.use('seaborn-v0_8-whitegrid')
        sns.set_palette("husl")

    def calculate_traffic_statistics(self) -> Dict:
        if self.df is None:
            return{}
        return {
            'temporal':{
                'total_duration_seconds': float(self.df['timestamp'].max() - self.df['timestamp'].min()),
                'packet_per_second': len(self.df)/max(1,(self.df['timestamp'].max() - self.df['timestamp'].min())),
                'avg_inter_arrival_ms': float(self.df['time_delta'].mean() * 1000) if 'time_delta' in self.df.columns else 0,
            },
            'size_characteristics':{
                'avg_packet_size': float(self.df['packet_length'].mean()),
                'size_variability': float(self.df['packet_length'].std()),
                'size_consistency': 'consistent' if self.df['packet_length'].std() < 50 else 'variable'
            },
            'protocol_behavior':{
                'read_write_ratio':self._calculate_read_write_ratio(),
                'most_common_function': self._get_most_common_function_code(),
                'function_diversity':self.df['function_code'].nunique()
            }
        }
    
    def _calculate_read_write_ratio(self) -> float:
        if 'is_read_operation' not in self.df.columns or 'is_writen_operation' not in self.df.columns:
            return 0.0
        read_count = self.df['is_read_operation'].sum()
        write_count = self.df['is_write_operation'].sum()
        return read_count / max(write_count, 1)

    def _get_most_common_function_code(self) -> Dict:
        if self.df is None or 'function_code' not in self.df.columns:
            return {}
        most_common = self.df['function_code'].mode()
        return{
            'code':int(most_common[0]) if len(most_common) > 0 else 0,
            'count':int(self.df['function_code'].value_counts().iloc[0]),
            'percentage':float((self.df['function_code'].value_counts().iloc[0] / len(self.df)) * 100)
       }
        
    def plot_traffic_overview(self, save_path: str = None) -> plt.Figure:
        fig, axes = plt.subplots(2,2, figsize = (15,10))
            
        #1. Function code distribution
        func_counts = self.df['function_code'].value_counts()
        axes[0,0].bar([str(code) for code in func_counts.index], func_counts.values)
        axes[0,0].set_title('Function Code Distribution')
        axes[0,0].set_xlabel('Function Code')
        axes[0,0].set_ylabel('Count')

        #2. Packet size over time
        axes[0,1].plot(self.df['timestamp'],self.df['packet_length'], 'b-', alpha = 0.7)
        axes[0,1].set_title('Packet Size Over Time')
        axes[0,1].set_xlabel('Timestamp')
        axes[0,1].set_ylabel('Packet Size (bytes)')
            
        #3. Packet size distribution
        axes[1,0].hist(self.df['packet_length'], bins=20, alpha = 0.7, color = 'green')
        axes[1,0].set_title('Packet Size Distribution')
        axes[1,0].set_xlabel('Packet Size (bytes)')
        axes[1,0].set_ylabel('Frequency')
            
        #4. Inter-arrival time (if available)
        if 'time_delta' in self.df.columns:
            axes[1,1].hist(self.df['time_delta'].dropna() * 1000, bins = 20, alpha = 0.7, color = 'orange')
            axes[1,1].set_title('Inter-Arrival Time Distribution')
            axes[1,1].set_xlabel('Time (ms)')
            axes[1,1].set_ylabel('Frequency')
            
        plt.tight_layout()
        if save_path:
            plt.savefig(save_path, dpi = 150, bbox_inches = 'tight')
        return fig
        
    def plot_entropy_analysis(self, save_path: str = None) -> plt.figure:
        if 'payload_entropy' not in self.df.columns:
            print("Entropy features not available")     
            return None
        fig, axes = plt.subplots(2,2, figsize = (15,10))
        
        #Payload entropy distribution
        axes[0,0].hist(self.df['payload_entropy'].dropna(), bins=20, alpha = 0.7)
        axes[0,0].axvline(3.5,color ='red', linestyle='--',alpha=0.7, label = 'Normal range')
        axes[0,0]. axvline(6.5, color ='red', linestyle = '--',alpha=0.7)
        axes[0,0].set_title('Payload Entropy Distribution')
        axes[0,0].set_xlabel('Entropy (bits)')
        axes[0,0].set_ylabel('Frequency')
        axes[0,0].legend()

        #Entropy over time
        axes[0,1].plot(self.df['timestamp'], self.df['payload_entropy'], 'g-', alpha = 0.7)
        axes[0,1].set_title('Payload Entropy Over Time')
        axes[0,1].set_xlabel('Timestamp')
        axes[0,1].set_ylabel('Entropy (bits)')
        
        #Entropy classification
        if 'entropy_classification' in self.df.columns:
            class_counts = self.df['entropy_classification'].value_counts()
            axes[1,0].pie(class_counts.values, labels = class_counts.index, autopct='%1.1f%%')
            axes[1,0].set_title('Entropy Classification')
        
        #Entropy vs Packet Size
        axes[1,1].scatter(self.df['packet_length'], self.df['payload_entropy'], alpha = 0.6)
        axes[1,1].set_title('Entropy vs Packet Size')
        axes[1,1].set_xlabel('Packet size(bytes)')
        axes[1,1].set_ylabel('Entropy (bits)')
        
        plt.tight_layout()
        if save_path:
            plt.savefig(save_path, dpi = 150, bbox_inches = 'tight')
        return fig

    def generate_analysis_report(self, output_file: str = 'analysis_report.md'):
        

        stats = self.calculate_traffic_statistics()
        
        report = f"""
#Modbus Traffic Analysis Report     
        
## Executive Summary
- **Total Pakcets**: {len(self.df)}
- **Analysis Duration**:{stats['temporal']['packet_per_second']:.2f} packets/second

## Traffic Characteristics
- **Average Packet Size**: {stats['size_characteristics']['avg_packet_size']:.1f} bytes
- **Size Consistency**: {stats['size_characteristics']['size_consistency']}
- **Read/Write Ratio**: {stats['protocol_behavior']['read_write_ratio']:.2f}

## Protocol Usage
- **Function Code Diversity**: {stats['protocol_behavior']['function_diversity']} unique codes
- **Most Common Function**: Code {stats['protocol_behavior']['most_common_function']['code']}
{stats['protocol_behavior']['most_common_function']['percentage']:.1f}% of traffic)

## Network Topology
- **Unique Sorces**: {self.df['src_ip'].nunique()}
- **Unique Destination**: {self.df['dst_ip'].nunique()}
- **Unique Units IDs**: {self.df['unit_id'].nunique()} 

## Detailed Function Code Distribution
"""
        func_dist = self.df['function_code'].value_counts()
        for code, count in func_dist.items():
            percentage = (count / len(self.df)) * 100
            report += f"- Code {code}: {count} packets ({percentage:.1f}%)\\n"

        with open(output_file, 'w') as f:
            f.write(report)
        print(f"Analysis report saved to: {output_file}")
        

    def detect_potential_anomalies(self) -> Dict:
        anomalies={}
        
        size_mean = self.df['packet_length'].mean()
        size_std = self.df['packet_length'].std()
        size_threshold = size_mean + 3 * size_std

        large_packets = self.df[self.df['packet_length'] > size_threshold]
        if len(large_packets) > 0:
            anomalies['usually_large_packets'] = {
                'count': len(large_packets),
                'details': large_packets[['timestamp', 'packet_length']].to_dict('records')
            }

        #Check for unusual timing (if available)
        if 'time_delta' in self.df.columns:
            time_threshold = self.df['time_delta'].quantile(0.99)
            slow_responses = self.df[self.df['time_delta'] > time_threshold]
            
            if len(slow_responses) > 0:
                anomalies['unusual_timing'] = {
                    'count': len(slow_responses),
                    'threshold_seconds': float(time_threshold)
            }
        return anomalies
    
    def export_analysis_results(self, output_dir: str = "analysis_output"):
        import os
        os.makedirs(output_dir,exist_ok=True)
        
        #Generate all outputs
        self.plot_traffic_overview(f"{output_dir}/traffic_verview.png")
        self.plot_entropy_analysis(f"{output_dir}/entropy_analysis.png")
        self.generate_analysis_report(f"{output_dir}/analysis_report.md")
               
        #Export data
        self.df.to_csv(f"{output_dir}/features.csv", index = False)
        
        #Export statics
        stats = self.calculate_traffic_statistics()
        with open(f"{output_dir}/statics.json",'w') as f:
            json.dump(stats, f, indent = 2)
        
        print(f"All analysis results exported to: {output_dir}/")

    def create_comparative_analysis(fingerprint_files: List[str], output_dir: str = "comparative_analysis"):
        import os
        os.makedirs(output_dir, exist_ok = True)
        # Implementation for comparing multiple analyses
        pass
    
    def quick_analysis(pcap_file:str,output_dir: str = "quick_analysis"):
        from feature_extractor import extract_features_from_pcap
        
        features_df = extract_features_from_pcap(pcap_file)
        
        if features_df.empty:
            print("No data to analyze")
            return
        
        analyzer = ModbusAnalysisTool(feautres_df)
        analyzer.export_analysis_results(output_dir)

        print(f"Quick analysis completed1 Results in {output_dir}/")   
