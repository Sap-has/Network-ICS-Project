# Week 3: Modbus Fingerprinting - Setup & Testing Guide

## Week 3 Goals
1. Set up packet capture and parsing pipeline
2. Extract fingerprinting features from Modbus traffic
3. Generate baseline "normal" fingerprints

---

## Setup Instructions

### Step 1: Install Dependencies

```bash
# Create virtual environment
python3 -m venv ids_env
source ids_env/bin/activate  # On Windows: ids_env\Scripts\activate

# Install required packages
pip install scapy numpy

# Install Git LFS for large PCAP files
# Visit: https://git-lfs.github.com/
```

### Step 2: Clone the ICS-PCAP Dataset

```bash
# Install Git LFS first, then:
git lfs clone https://github.com/automayt/ICS-pcap.git
cd ICS-pcap
```

### Step 3: Locate Modbus PCAP Files

The repository contains various protocols. Look for Modbus files:
```bash
# Search for Modbus-related files
find . -name "*modbus*" -o -name "*MODBUS*"
```

Common Modbus PCAP files in the dataset:
- `modbus.pcap`
- `modbus_*.pcap`
- Check subdirectories for protocol-specific captures

---

## Running the Fingerprinting Tool

### Basic Usage

```bash
# Analyze a single PCAP file
python modbus_fingerprint.py path/to/modbus.pcap

# Specify output file
python modbus_fingerprint.py path/to/modbus.pcap output_fingerprint.json
```

### Expected Output

The tool will display:
1. **Summary Statistics**: Packet counts, timing, function codes
2. **Feature Distributions**: What protocols operations are being performed
3. **JSON Fingerprint**: Saved for later comparison

---

## What to Analyze This Week

### Task 1: Single PCAP Analysis (Luis - Lead)
**Goal**: Verify the parser works correctly

```bash
# Pick one Modbus PCAP file
python modbus_fingerprint.py ICS-pcap/modbus.pcap normal_baseline.json
```

**Checklist**:
- [ ] Script runs without errors
- [ ] Modbus packets are correctly identified
- [ ] Function codes are properly decoded
- [ ] Timing information is extracted
- [ ] Entropy values are calculated

### Task 2: Feature Validation (Efrain - Lead)
**Goal**: Verify extracted features make sense

**Questions to answer**:
1. What's the most common function code? (Should be Read/Write operations)
2. What's the typical packet size range?
3. What's the inter-arrival time pattern? (Should be relatively consistent for normal traffic)
4. What's the entropy range? (Low entropy = repetitive data, high = random/encrypted)

**Create a validation script**:
```python
import json

# Load fingerprint
with open('normal_baseline.json', 'r') as f:
    fp = json.load(f)

# Check function codes
print("Function Code Analysis:")
for func, count in fp['statistics']['function_code_distribution'].items():
    print(f"  {func}: {count}")

# Check if features are reasonable
assert fp['statistics']['total_packets'] > 0, "No packets found!"
assert 'Read' in str(fp['statistics']['function_code_distribution']), "No read operations?"
```

### Task 3: Multiple PCAP Comparison (Luis + Efrain)
**Goal**: Build multiple fingerprints to identify patterns

```bash
# Process multiple files
for pcap in ICS-pcap/*modbus*.pcap; do
    python modbus_fingerprint.py "$pcap" "fingerprint_$(basename $pcap .pcap).json"
done
```

**Analysis**:
- Compare fingerprints from different captures
- Identify common patterns across "normal" traffic
- Note any anomalies or variations

---

## Features Explained

### 1. Packet Length Distribution
- **What**: Size of each Modbus packet in bytes
- **Why**: Different operations have different packet sizes
- **Normal behavior**: Relatively consistent sizes for each function code

### 2. Function Code Distribution
- **What**: Frequency of each Modbus operation (read/write registers, coils, etc.)
- **Why**: Normal operations follow predictable patterns
- **Normal behavior**: Mostly reads (3, 4), some writes (6, 16)

### 3. Inter-Arrival Times
- **What**: Time between consecutive packets
- **Why**: ICS systems often operate on fixed polling cycles
- **Normal behavior**: Consistent timing (e.g., every 100ms, 1s)

### 4. Payload Entropy
- **What**: Randomness of packet data (0 = all same, 8 = random)
- **Why**: Control data is typically structured and predictable
- **Normal behavior**: Low to medium entropy (2-5 bits)

### 5. Unit ID Distribution
- **What**: Which Modbus devices are being addressed
- **Why**: Identifies network topology and communication patterns
- **Normal behavior**: Fixed set of unit IDs with consistent traffic

---

## Deliverables for End of Week 3

### 1. Working Code
- [ ] `modbus_fingerprint.py` runs successfully
- [ ] Processes at least 3 different Modbus PCAP files
- [ ] Generates valid JSON output

### 2. Documentation
- [ ] **README.md**: How to run the tool
- [ ] **FEATURES.md**: Explanation of each feature and why it matters
- [ ] **RESULTS.md**: Summary of findings from test PCAPs

### 3. Baseline Fingerprints
- [ ] At least 3 "normal" traffic fingerprints
- [ ] Documented characteristics of normal behavior
- [ ] Notes on any interesting patterns observed

### 4. Test Report
Create a document with:
```markdown
# Week 3 Test Results

## Dataset Information
- Source: ICS-pcap repository
- Files analyzed: [list files]
- Total packets processed: X

## Feature Extraction Results
### Packet Lengths
- Mean: X bytes
- Range: X-X bytes
- Interpretation: [normal/anomalous?]

### Function Codes
- Most common: [Read Holding Registers (3)]
- Distribution: [percentages]
- Interpretation: [typical SCADA polling pattern]

### Timing
- Inter-arrival mean: X ms
- Pattern: [consistent/variable]
- Interpretation: [likely 1-second polling cycle]

### Entropy
- Mean: X bits
- Interpretation: [structured control data as expected]

## Issues Encountered
1. [Issue 1 and solution]
2. [Issue 2 and solution]

## Next Steps for Week 4
- Extend to DNP3 protocol
- Add anomaly detection logic
- Optimize performance
```

---

## Troubleshooting

### Common Issues

**Problem**: "No module named 'scapy'"
```bash
pip install scapy
```

**Problem**: "Permission denied" on Linux
```bash
# Run with sudo for live capture (not needed for PCAP files)
sudo python modbus_fingerprint.py capture.pcap
```

**Problem**: "No Modbus packets found"
- Check if PCAP contains Modbus (port 502)
- Verify PCAP file is not corrupted
- Try opening in Wireshark first to confirm Modbus traffic exists

**Problem**: Git LFS files are pointers, not actual files
```bash
# Re-clone with LFS
git lfs install
git lfs pull
```

---

## Learning Resources

### Understanding Modbus
- [Modbus Protocol Spec (PDF)](https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf)
- Function codes reference
- Typical SCADA communication patterns

### Wireshark Analysis
```bash
# Open PCAP in Wireshark
wireshark modbus.pcap

# Filter for Modbus
# Filter: tcp.port == 502
```

---

## Week 3 Timeline

**Monday-Tuesday**: Setup and basic parsing
- Install dependencies
- Get basic parser working
- Test on one PCAP file

**Wednesday-Thursday**: Feature extraction
- Implement all 5 feature types
- Test on multiple PCAPs
- Create baseline fingerprints

**Friday**: Testing and documentation
- Run comprehensive tests
- Document findings
- Prepare for Week 4 (DNP3 extension)

---

## Team Coordination

### Daily Standup Questions
1. What did you complete yesterday?
2. What are you working on today?
3. Any blockers?

### Communication
- Share PCAP files via shared drive
- Commit code to team repository
- Document issues in shared document

### Code Review
- Luis reviews Efrain's code
- Efrain reviews Luis's code
- Diego and Epifanio provide feedback on design

---

## Success Criteria

By end of Week 3, you should be able to:
- Capture and parse Modbus TCP packets
- Extract 5 key fingerprinting features
- Generate JSON fingerprints
- Explain what "normal" Modbus traffic looks like
- Identify at least 3 distinguishing characteristics

