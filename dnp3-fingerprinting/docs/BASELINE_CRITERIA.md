# Baseline Criteria for Normal Modbus Traffic

## Normal Traffic Characteristics

### 1. Communication Patterns
**Polling Behavior**
- Regular, periodic queries from master to slaves
- Inter-arrival time: 10-1000ms (mean), typically 100-500ms
- Coefficient of variation (CV) < 0.5 for timing regularity

**Request-Response Pairs**
- Request-response ratio: 0.9-1.1
- Response delay: 1-100ms (95th percentile < 150ms)
- Orphaned packets: < 1% of total traffic

### 2. Protocol Compliance
**Valid Function Codes**
- Standard codes: 1, 2, 3, 4, 5, 6, 15, 16, 23
- Function code 3 (Read Holding Registers): 40-70% of traffic
- Function code 16 (Write Multiple Registers): 10-30% of traffic
- Error responses (FC >= 128): < 2% of traffic

**Message Structure**
- Protocol ID: always 0
- Unit ID range: 1-247
- Transaction ID: sequential or cyclic patterns
- Length field consistency: matches actual PDU length

### 3. Packet Characteristics
**Size Distribution**
- Mean: 60-300 bytes
- Standard deviation: 10-50 bytes
- Minimum: 12 bytes (MBAP + FC)
- Maximum: 260 bytes (standard Modbus limit)
- Coefficient of variation: 0.1-0.5

**Entropy Characteristics**
- Payload entropy: 3.5-6.5 bits
- Header entropy: 2.0-4.0 bits
- Full packet entropy: 3.0-6.0 bits
- Low entropy (< 3.5): structured control data
- High entropy (> 6.5): potential encryption/obfuscation

### 4. Temporal Features
**Inter-Arrival Time (IAT)**
- Mean IAT: 10-1000ms
- IAT standard deviation: 5-500ms
- IAT coefficient of variation: < 0.5 (regular polling)
- IAT skewness: -1 to 1 (symmetric distribution)
- No burst patterns: max IAT / mean IAT < 5

**Periodicity**
- Autocorrelation at polling interval: > 0.7
- Periodic component detectable via FFT
- Low jitter: IAT std / IAT mean < 0.3

### 5. Flow Characteristics
**Per-Flow Metrics**
- Packets per flow: 10-10000
- Flow duration: 1-86400 seconds (continuous operation)
- Bidirectional flows: request-response pairing
- Flow symmetry: forward/backward packet ratio 0.8-1.2

**Function Code Patterns**
- Function code diversity: 2-8 unique codes
- Dominant function code: > 30% of traffic
- Sequential function code changes: < 30% of packets
- Function code stability in 10-packet window: > 50%

### 6. Network Topology
**Address Patterns**
- Unique source IPs: 1-5 (master devices)
- Unique destination IPs: 1-50 (slave devices)
- Unique unit IDs: 1-50 (slave addresses)
- IP-to-Unit ID consistency: stable mapping

## Anomaly Indicators

### Statistical Anomalies
1. **Packet Size**: > 2σ from baseline mean
2. **IAT**: > 2σ from baseline mean or CV > 0.7
3. **Entropy**: < 2.0 or > 7.0 bits
4. **Function Code**: reserved codes (7-14, 17-19, 24-127)

### Pattern Anomalies
1. **Burst Traffic**: IAT drops below 1ms for > 10 consecutive packets
2. **Orphaned Requests**: > 5% requests without responses
3. **Function Code Scanning**: > 10 unique function codes
4. **Rapid Function Changes**: > 50% sequential changes

### Protocol Violations
1. **Invalid Protocol ID**: protocol_id != 0
2. **Invalid Unit ID**: unit_id = 0 or > 247
3. **Length Mismatch**: declared length != actual PDU length
4. **Malformed Packets**: incomplete headers or truncated data

## Baseline Establishment

### Data Collection Requirements
- Duration: 24-48 hours minimum
- Operational states: include normal production cycles
- Traffic volume: >= 10,000 packets
- Time coverage: multiple shifts/operational modes

### Feature Aggregation Windows
- Short-term (10-packet rolling window)
- Medium-term (60-second sliding window)
- Long-term (5-minute aggregation)

### Statistical Thresholds
- Confidence level: 95% (±2σ)
- Minimum packet count per unit ID: 100
- Minimum function code occurrence: 10

### Validation Criteria
- False positive rate: < 5% on validation set
- Coverage: baseline captures >= 95% of normal behavior
- Stability: metrics consistent across collection period