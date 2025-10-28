# Project Structure and Testing Framework

## Directory Structure
```
modbus-fingerprinting/
├── data/
│   ├── raw/                    # Original PCAP files
│   ├── processed/              # Extracted features
│   └── baselines/              # Baseline fingerprints
├── src/
│   ├── extraction/             # Feature extraction modules
│   │   ├── packet_parser.py
│   │   ├── feature_extractor.py
│   │   └── entropy_calculator.py
│   ├── analysis/               # Analysis and fingerprinting
│   │   ├── baseline_builder.py
│   │   ├── anomaly_detector.py
│   │   └── visualizer.py
│   └── utils/                  # Helper functions
│       ├── pcap_loader.py
│       └── logging_config.py
├── tests/
│   ├── test_extraction.py
│   ├── test_analysis.py
│   └── test_integration.py
├── docs/
│   ├── DATASET_CATALOG.md
│   ├── FEATURE_SPECIFICATIONS.md
│   ├── BASELINE_CRITERIA.md
│   └── PROJECT_STRUCTURE.md
├── notebooks/                  # Jupyter notebooks for exploration
│   ├── exploratory_analysis.ipynb
│   └── visualization.ipynb
├── requirements.txt
├── setup.py
└── README.md
```

## Testing Framework

### Unit Tests
**Feature Extraction Tests**
- Verify packet parsing accuracy
- Validate entropy calculations
- Test timing feature extraction
- Check protocol-specific feature detection

**Baseline Building Tests**
- Test statistical aggregation
- Validate threshold calculation
- Verify fingerprint serialization

### Integration Tests
**End-to-End Pipeline**
- PCAP → Feature extraction → Baseline creation
- Test with known-good traffic samples
- Verify output format consistency

### Validation Tests
**Anomaly Detection**
- Test against known attack patterns
- Measure false positive/negative rates
- Validate detection thresholds

## Manual Inspection Findings

### Sample PCAP Analysis (Initial Observations)
**File**: [pcap_filename_1]
- **Traffic Pattern**: [Describe observed pattern]
- **Function Codes Observed**: [List]
- **Average Packet Size**: [Value]
- **Inter-arrival Times**: [Pattern description]
- **Anomalies Found**: [Any unusual behavior]

**File**: [pcap_filename_2]
- **Traffic Pattern**: [Describe observed pattern]
- **Function Codes Observed**: [List]
- **Average Packet Size**: [Value]
- **Inter-arrival Times**: [Pattern description]
- **Anomalies Found**: [Any unusual behavior]

### Key Observations
1. [Observation about normal traffic patterns]
2. [Observation about protocol usage]
3. [Observation about timing characteristics]
4. [Potential challenges identified]

## Test Plan

### Phase 1: Component Testing
- Test individual feature extractors
- Validate data preprocessing
- Verify statistical calculations

### Phase 2: Integration Testing
- Test full extraction pipeline
- Validate baseline creation
- Test anomaly detection logic

### Phase 3: Validation Testing
- Test against labeled dataset
- Measure accuracy metrics
- Tune detection thresholds

### Phase 4: Performance Testing
- Benchmark processing speed
- Test with large PCAP files
- Optimize bottlenecks

## Testing Tools
- **pytest**: Python testing framework
- **Wireshark**: Manual PCAP inspection
- **tcpdump**: Quick packet analysis
- **tshark**: Automated PCAP queries

## Success Criteria
- All unit tests pass (100% coverage on core functions)
- Integration tests demonstrate correct pipeline flow
- Anomaly detection achieves > 90% accuracy on labeled data
- False positive rate < 5%
- Processing speed: > 1000 packets/second

## Known Challenges
1. Handling malformed packets gracefully
2. Dealing with incomplete TCP streams
3. Distinguishing legitimate variations from attacks
4. Managing memory with large PCAP files

## Next Steps
1. Implement basic packet parser
2. Create test fixtures from sample PCAPs
3. Build test harness for feature extractors
4. Document test results and edge cases