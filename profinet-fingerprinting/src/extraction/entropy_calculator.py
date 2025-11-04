import numpy as np
from typing import Optional
from collections import Counter


class EntropyCalculator:
    """
    Calculate Shannon entropy for packet data.
    
    Shannon Entropy Formula: H(X) = -Σ p(x) * log2(p(x))
    where p(x) is the probability of byte value x
    
    Entropy ranges from 0 (all same byte) to 8 (perfectly random)
    """
    @staticmethod
    def calculate_shannon_entropy(data: bytes) -> float:
        if not data or len(data) == 0:
            return 0.0
        
        # Count frequency of each byte value (0-255)
        byte_counts = Counter(data)
        data_len = len(data)
        
        # Calculate probability distribution
        entropy = 0.0
        for count in byte_counts.values():
            if count == 0:
                continue
            probability = count / data_len
            entropy -= probability * np.log2(probability)
        
        return entropy
    
    @staticmethod
    def calculate_payload_entropy(payload: Optional[bytes]) -> float:
        if payload is None or len(payload) == 0:
            return 0.0
        
        return EntropyCalculator.calculate_shannon_entropy(payload)
    
    @staticmethod
    def calculate_header_entropy(header: bytes) -> float:
        if not header or len(header) < 7:
            return 0.0
        
        # Use only first 7 bytes (MBAP header)
        mbap_header = header[:7]
        return EntropyCalculator.calculate_shannon_entropy(mbap_header)
    
    @staticmethod
    def calculate_full_packet_entropy(raw_data: bytes) -> float:
        return EntropyCalculator.calculate_shannon_entropy(raw_data)
    
    @staticmethod
    def classify_entropy(entropy: float) -> str:
        if entropy < 2.0:
            return "Very Low (Highly repetitive)"
        elif entropy < 4.0:
            return "Low (Structured data)"
        elif entropy < 6.0:
            return "Medium (Mixed content)"
        elif entropy < 7.0:
            return "High (Varied data)"
        else:
            return "Very High (Random/Encrypted)"
    
    @staticmethod
    def is_entropy_normal(entropy: float, expected_range: tuple = (3.5, 6.5)) -> bool:
        min_entropy, max_entropy = expected_range
        return min_entropy <= entropy <= max_entropy


def calculate_entropy_statistics(entropy_values: list) -> dict:
    if not entropy_values:
        return {
            'mean': 0.0,
            'std': 0.0,
            'min': 0.0,
            'max': 0.0,
            'median': 0.0
        }
    
    entropy_array = np.array(entropy_values)
    
    return {
        'mean': float(np.mean(entropy_array)),
        'std': float(np.std(entropy_array)),
        'min': float(np.min(entropy_array)),
        'max': float(np.max(entropy_array)),
        'median': float(np.median(entropy_array)),
        'q25': float(np.percentile(entropy_array, 25)),
        'q75': float(np.percentile(entropy_array, 75))
    }
