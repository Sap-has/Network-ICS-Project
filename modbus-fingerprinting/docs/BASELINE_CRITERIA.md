# Baseline Criteria for Normal Modbus Traffic

## Overview
This document defines what constitutes "normal" Modbus traffic behavior for fingerprinting legitimate SCADA operations.

## Normal Traffic Characteristics

### 1. Communication Patterns
**Polling Behavior**
- Regular, periodic queries from master to slaves
- Consistent polling intervals (typically 100ms - 5 seconds)
- Predictable query sequences

**Request-Response Pairs**
- Every request has a matching response
- Response delay typically < 100ms
- No orphaned requests or responses

### 2. Protocol Compliance
**Valid Function Codes**
- Use of standard Modbus function codes: 1-6, 15-16, 20-24
- Function code 3 (Read Holding Registers) most common
- No reserved or undefined function codes

**Proper Message Structure**
- Correct MBAP header format (Modbus TCP)
- Valid unit identifiers (1-247)
- Appropriate data lengths for each function code

### 3. Network Behavior
**Connection Stability**
- Long-lived TCP connections
- Minimal retransmissions
- Low packet loss rate (< 0.1%)

**Traffic Volume**
- Consistent packet rate
- No sudden traffic bursts
- Predictable bandwidth usage

### 4. Temporal Patterns
**Time-Based Regularity**
- Operations aligned with industrial schedules
- Reduced activity during off-hours (if applicable)
- No rapid command floods

### 5. Data Patterns
**Register Access**
- Consistent register addresses accessed
- Read operations more frequent than writes
- Write operations follow logical sequences

## Anomaly Indicators

### Deviations from Normal
1. **Malformed Packets**: Invalid headers, incorrect lengths
2. **Illegal Function Codes**: Reserved or proprietary codes
3. **Timing Anomalies**: Unusual inter-arrival times, response delays
4. **Volume Spikes**: Sudden increase in traffic rate
5. **Access Violations**: Unusual register addresses, excessive writes

## Baseline Establishment Process

### Phase 1: Data Collection
- Collect at least 24-48 hours of normal traffic
- Include various operational states
- Ensure no attacks or anomalies present

### Phase 2: Feature Extraction
- Extract all features defined in FEATURE_SPECIFICATIONS.md
- Calculate statistical distributions
- Identify patterns and correlations

### Phase 3: Fingerprint Creation
- Build statistical model of normal behavior
- Define confidence intervals (95% confidence level)
- Document typical operational patterns

### Phase 4: Validation
- Test baseline against known-good traffic
- Adjust thresholds to minimize false positives
- Document edge cases and exceptions

## ICSTracker Methodology Alignment
- **Entropy Analysis**: Monitor payload randomness
- **Temporal Fingerprinting**: Track timing patterns
- **Protocol State Machine**: Model valid state transitions
- **Behavioral Modeling**: Capture operational context

## Exclusions from Baseline
- Startup/shutdown sequences
- Maintenance windows
- Configuration changes
- Error conditions and retries

## Documentation Requirements
Each baseline fingerprint should include:
- Time period of data collection
- System configuration details
- Operational state during collection
- Statistical summary of all features
- Known anomalies excluded

## References
- ICSTracker: A Physical Side-Channel Attack on ICS Networks
- Modbus Application Protocol Specification V1.1b3
- NIST Guide to Industrial Control Systems Security