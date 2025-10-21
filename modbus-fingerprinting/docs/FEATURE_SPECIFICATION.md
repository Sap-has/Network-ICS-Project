# Modbus Feature Extraction Specifications

## Feature Categories

### 1. Basic Packet Features
| Feature | Description | Expected Range | Units |
|---------|-------------|----------------|-------|
| packet_length | Total packet size | 12-260 | bytes |
| modbus_length | MBAP length field | 2-254 | bytes |
| data_length | PDU data field length | 0-252 | bytes |
| transaction_id | MBAP transaction ID | 0-65535 | integer |
| protocol_id | MBAP protocol ID | 0 | integer |
| unit_id | Slave device address | 1-247 | integer |
| function_code | Modbus function code | 1-127 | integer |

### 2. Statistical Packet Features (10-packet rolling window)
| Feature | Description | Expected Range | Units |
|---------|-------------|----------------|-------|
| packet_length_mean_10 | Mean packet size | 60-300 | bytes |
| packet_length_std_10 | Std dev of packet size | 10-50 | bytes |
| packet_length_max_10 | Maximum packet size | 12-260 | bytes |
| packet_length_min_10 | Minimum packet size | 12-260 | bytes |
| packet_length_cv_10 | Coefficient of variation | 0.1-0.5 | ratio |

### 3. Timing Features
| Feature | Description | Expected Range | Units |
|---------|-------------|----------------|-------|
| time_delta | Inter-arrival time | 0.001-10 | seconds |
| time_delta_ms | Inter-arrival time | 1-10000 | milliseconds |
| time_delta_mean_10 | Mean IAT (10 packets) | 0.01-1.0 | seconds |
| time_delta_std_10 | Std dev IAT (10 packets) | 0.005-0.5 | seconds |
| time_delta_cv_10 | Coefficient of variation | 0.0-0.7 | ratio |
| time_delta_min_10 | Minimum IAT | 0.001-1.0 | seconds |
| time_delta_max_10 | Maximum IAT | 0.01-10.0 | seconds |

### 4. Entropy Features
| Feature | Description | Expected Range | Units |
|---------|-------------|----------------|-------|
| payload_entropy | Shannon entropy of PDU data | 3.5-6.5 | bits |
| header_entropy | Shannon entropy of MBAP header | 2.0-4.0 | bits |
| full_packet_entropy | Shannon entropy of entire packet | 3.0-6.0 | bits |
| payload_entropy_mean_10 | Rolling mean entropy | 3.5-6.5 | bits |
| payload_entropy_std_10 | Rolling std entropy | 0.1-1.5 | bits |
| payload_entropy_max_10 | Rolling max entropy | 3.5-7.0 | bits |
| payload_entropy_min_10 | Rolling min entropy | 2.0-6.5 | bits |

### 5. Function Code Features
| Feature | Description | Expected Range | Units |
|---------|-------------|----------------|-------|
| function_code | Current function code | 1-127 | integer |
| fc_1 through fc_127 | One-hot encoded FCs | 0 or 1 | binary |
| is_read_operation | Read operations (FC 1-4) | 0 or 1 | binary |
| is_write_operation | Write operations (FC 5,6,15,16) | 0 or 1 | binary |
| is_error_response | Error response (FC ≥ 128) | 0 or 1 | binary |
| function_code_changes | Sequential FC changes | 0 or 1 | binary |
| function_code_stability_10 | % unchanged FCs in window | 0.0-1.0 | ratio |

### 6. Flow-Level Features
| Feature | Description | Expected Range | Units |
|---------|-------------|----------------|-------|
| unique_src_ips | Number of source IPs | 1-10 | count |
| unique_dst_ips | Number of destination IPs | 1-100 | count |
| unique_unit_ids | Number of unit IDs | 1-50 | count |
| packets_per_src | Packets per source IP | 1-100000 | count |
| packets_per_dst | Packets per destination IP | 1-100000 | count |
| packets_per_unit | Packets per unit ID | 1-100000 | count |

### 7. Protocol Validation Features
| Feature | Description | Expected Range | Units |
|---------|-------------|----------------|-------|
| is_valid | Protocol compliance | True/False | boolean |
| protocol_id_valid | Protocol ID = 0 | True/False | boolean |
| unit_id_valid | Unit ID in 1-247 | True/False | boolean |
| function_code_valid | FC in valid range | True/False | boolean |
| length_consistent | Length field matches actual | True/False | boolean |

### 8. Derived Statistical Features
| Feature | Description | Calculation | Units |
|---------|-------------|-------------|-------|
| burst_indicator | Rapid packet arrival | IAT < 5ms | binary |
| periodicity_score | Timing regularity | 1 - CV of IAT | ratio |
| entropy_stability | Entropy consistency | 1 / (1 + std entropy) | ratio |
| traffic_intensity | Packet rate | packets per second | rate |
| read_write_ratio | Read vs write balance | read_ops / write_ops | ratio |

## Feature Extraction Windows

### Rolling Window Features (10 packets)
- Packet length statistics
- Timing statistics
- Entropy statistics
- Function code stability

### Sliding Window Features (60 seconds)
- Aggregate packet counts
- Function code distribution
- Network topology metrics
- Protocol violation rates

### Session Features (per flow)
- Total packets
- Flow duration
- Dominant function code
- Request-response pairing

## Feature Engineering Guidelines

### Normalization
- Z-score normalization for continuous features
- Min-max scaling for bounded features (0-1)
- Log transformation for skewed distributions (IAT)

### Missing Value Handling
- Forward fill for temporal features
- Zero fill for first window (no history)
- Mean imputation for isolated missing values

### Outlier Detection Thresholds
- ±2σ: flag for investigation
- ±3σ: strong anomaly indicator
- IQR method: Q1 - 1.5×IQR, Q3 + 1.5×IQR

## Feature Importance

### High-Importance Features (Primary Detection)
1. payload_entropy
2. time_delta_mean_10
3. function_code
4. packet_length_mean_10
5. is_valid

### Medium-Importance Features (Secondary Detection)
1. time_delta_cv_10
2. function_code_stability_10
3. header_entropy
4. packet_length_cv_10
5. is_error_response

### Low-Importance Features (Context)
1. transaction_id
2. unique_src_ips
3. unit_id
4. protocol_id

## Extraction Performance Requirements
- Processing rate: > 1000 packets/second
- Memory usage: < 100 MB per 10,000 packets
- Feature computation latency: < 1ms per packet
- Window update overhead: < 0.1ms per packet