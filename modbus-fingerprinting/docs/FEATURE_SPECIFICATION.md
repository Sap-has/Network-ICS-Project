# Modbus Feature Extraction Specifications

## Overview
This document defines the features to be extracted from Modbus traffic and their expected normal ranges.

## Feature Categories

### 1. Packet Size Features
| Feature | Description | Expected Normal Range | Units |
|---------|-------------|----------------------|-------|
| Mean packet size | Average size of Modbus packets | 60-300 bytes | bytes |
| Std dev packet size | Standard deviation of packet sizes | 10-50 bytes | bytes |
| Min/Max packet size | Smallest and largest packets | Min: 12, Max: 260 | bytes |

### 2. Timing Features
| Feature | Description | Expected Normal Range | Units |
|---------|-------------|----------------------|-------|
| Inter-arrival time (mean) | Average time between packets | 10-1000 ms | milliseconds |
| Inter-arrival time (std) | Timing variation | 5-500 ms | milliseconds |
| Request-response delay | Time between query and response | 1-100 ms | milliseconds |

### 3. Entropy Features
| Feature | Description | Expected Normal Range | Units |
|---------|-------------|----------------------|-------|
| Payload entropy | Shannon entropy of packet data | 3.5-6.5 | bits |
| Header entropy | Entropy of protocol headers | 2.0-4.0 | bits |

### 4. Protocol-Specific Features
| Feature | Description | Expected Normal Range | Units |
|---------|-------------|----------------------|-------|
| Function code distribution | Common Modbus function codes | FC 1,2,3,4,5,6,15,16 | - |
| Transaction ID sequence | Transaction identifier patterns | Sequential/cyclic | - |
| Unit identifier | Slave/device addresses | 1-247 | address |

### 5. Flow Features
| Feature | Description | Expected Normal Range | Units |
|---------|-------------|----------------------|-------|
| Packets per flow | Number of packets per connection | 10-1000 | count |
| Flow duration | Length of communication session | 1-3600 seconds | seconds |
| Request/response ratio | Balance of queries vs responses | 0.9-1.1 | ratio |

## Extraction Method
- **Tool**: Scapy with custom Modbus layer parser
- **Window Size**: 60-second sliding window
- **Aggregation**: Per-flow and global statistics

## Anomaly Thresholds
- Values beyond 2 standard deviations from baseline trigger alerts
- Multiple feature violations indicate potential attack

## References
- Modbus Protocol Specification v1.1b3
- ICSTracker feature extraction methodology