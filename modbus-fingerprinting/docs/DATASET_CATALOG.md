# Modbus PCAP Dataset Catalog

## Overview
This document catalogs all Modbus PCAP files available in the ICS-PCAP repository for analysis.

## Dataset Information
- **Repository**: ICS-PCAP
- **Protocol Focus**: Modbus TCP/RTU
- **Extraction Date**: [DATE]

## Available PCAP Files

### Normal Traffic
| Filename | File Size | Packet Count | Duration | Notes |
|----------|-----------|--------------|----------|-------|
| modbus_normal_01.pcap | [SIZE] | [COUNT] | [TIME] | Baseline traffic |
| modbus_normal_02.pcap | [SIZE] | [COUNT] | [TIME] | Baseline traffic |

### Attack Traffic
| Filename | File Size | Packet Count | Duration | Attack Type |
|----------|-----------|--------------|----------|-------------|
| modbus_attack_01.pcap | [SIZE] | [COUNT] | [TIME] | [TYPE] |
| modbus_attack_02.pcap | [SIZE] | [COUNT] | [TIME] | [TYPE] |

## Summary Statistics
- **Total PCAP Files**: [NUMBER]
- **Total Packets**: [NUMBER]
- **Total Size**: [SIZE]
- **Normal Traffic Files**: [NUMBER]
- **Attack Traffic Files**: [NUMBER]

## Extraction Commands Used
```bash
# Command to count packets
tcpdump -r <filename> | wc -l

# Command to get file size
ls -lh <filename>
```

## Notes
- All files use Git LFS for storage
- Modbus traffic identified on ports 502 (TCP) and custom RTU configurations
- Files verified for integrity after LFS pull