# IP Address Parsing Solution

A comprehensive set of Python scripts for cleaning, analyzing, and organizing IP address lists from clients. Perfect for security analysts, network engineers, and anyone who needs to process messy IP lists into clean, professional output.

## What This Toolkit Does

When clients send you messy lists of IP addresses with duplicates and mixed formats, this toolkit provides a complete solution:

1. **Clean & Deduplicate** → `ip_extractor.py` removes duplicates and normalizes formats
2. **Analyze & Count** → `ip_counter.py` provides detailed statistics and counts
3. **Filter by Type** → `public_ip_finder.py` and `private_ip_finder.py` separate external vs internal IPs
4. **Consolidate Ranges** → Automatically groups sequential IPs into efficient CIDR blocks

## Quick Start Workflow

### 1. **Clean & Deduplicate** (Always start here)
```bash
python ip_extractor.py client_messy_list.txt --output clean_deduplicated.txt
```

### 2. **Analyze & Count** (Understand what you're working with)
```bash
python ip_counter.py clean_deduplicated.txt --detailed
```

### 3. **Filter by Use Case** (Choose based on your needs)

#### For External/Internet Scans (Firewall Rules, Outbound Monitoring):
```bash
python public_ip_finder.py clean_deduplicated.txt --output external_targets.txt
```

#### For Internal Network Scans (Internal Security, Network Documentation):
```bash
python private_ip_finder.py clean_deduplicated.txt --output internal_targets.txt
```

## Individual Tool Details

### **IP Extractor** (`ip_extractor.py`)
**Purpose:** Clean up messy IP lists and remove duplicates

**What it handles:**
- Mixed formats (individual IPs, ranges, CIDR notation)
- Duplicate IP addresses
- Extra spaces, weird characters, encoding issues
- Converts longhand ranges (192.168.1.1-192.168.1.100) to CIDR notation
- Removes /32 CIDR notation (represents single IPs)

**Example:**
```bash
# Input: messy_client_list.txt
192.168.1.1, 192.168.1.1, 192.168.1.2, 10.0.0.0/24, 8.8.8.8

# Output: clean_deduplicated.txt
192.168.1.1, 192.168.1.2, 10.0.0.0/24, 8.8.8.8
```

### **IP Counter** (`ip_counter.py`)
**Purpose:** Analyze and count IP addresses in your cleaned list

**What it provides:**
- Total IP count (including ranges)
- Public vs Private IP breakdown
- Detailed analysis of each IP type
- Useful for understanding scope and planning

**Example:**
```bash
python ip_counter.py clean_deduplicated.txt --detailed

# Output:
IP Address Analysis
==================
Summary:
  Total IPs: 258
  Public IPs: 1
  Private IPs: 257
  Individual IPs: 3
  IPs in Ranges: 255
```

### **Public IP Finder** (`public_ip_finder.py`)
**Purpose:** Extract only external/Internet-facing IP addresses

**Perfect for:**
- Firewall outbound rules
- External security scans
- Internet-facing service monitoring
- Compliance reporting (external assets)

**Example:**
```bash
python public_ip_finder.py clean_deduplicated.txt --output external_targets.txt

# Output:
8.8.8.8, 203.0.113.0/24
```

### **Private IP Finder** (`private_ip_finder.py`)
**Purpose:** Extract only internal/private network IP addresses

**Perfect for:**
- Internal security scans
- Network documentation
- Internal asset inventory
- Compliance reporting (internal assets)

**Example:**
```bash
python private_ip_finder.py clean_deduplicated.txt --output internal_targets.txt

# Output:
192.168.1.0/30, 10.0.0.0/24, 127.0.0.1
```

## Complete Example Workflow

### **Scenario:** Client sends messy IP list for security assessment

**1. Initial Client File** (`client_ips.txt`):
```
192.168.1.1, 192.168.1.1, 192.168.1.2, 192.168.1.3, 10.0.0.0/24, 8.8.8.8, 203.0.113.0/24
```

**2. Clean & Deduplicate:**
```bash
python ip_extractor.py client_ips.txt --output clean_list.txt
# Result: 192.168.1.1, 192.168.1.2, 192.168.1.3, 10.0.0.0/24, 8.8.8.8, 203.0.113.0/24
```

**3. Analyze & Count:**
```bash
python ip_counter.py clean_list.txt --detailed
# Shows: 258 total IPs (3 individual + 255 from ranges), 1 public, 257 private
```

**4. Create External Targets List:**
```bash
python public_ip_finder.py clean_list.txt --output external_targets.txt
# Result: 8.8.8.8, 203.0.113.0/24
```

**5. Create Internal Targets List:**
```bash
python private_ip_finder.py clean_list.txt --output internal_targets.txt
# Result: 192.168.1.0/30, 10.0.0.0/24
```

**6. Use Results:**
- `external_targets.txt` → External security scanner configuration
- `internal_targets.txt` → Internal network scanner configuration

## Advanced Features

### **CIDR Consolidation**
All tools automatically consolidate sequential IPs into efficient CIDR ranges:
- `192.168.1.1, 192.168.1.2, 192.168.1.3` becomes `192.168.1.0/30`
- Reduces list size and improves firewall rule efficiency

### **Smart Input Handling**
- Automatically detects and handles various file encodings
- Cleans up common formatting issues
- Provides helpful error messages and troubleshooting tips

### **Flexible Output Options**
- Print to screen or save to files
- Detailed analysis mode or simple comma-separated lists
- Verbose mode for debugging

## Common Use Cases

### **Security Assessments**
1. Extract client IP list → Clean with `ip_extractor.py`
2. Count scope with `ip_counter.py`
3. Separate external vs internal with finder scripts
4. Configure scanners appropriately

### **Firewall Rule Creation**
1. Clean IP list with `ip_extractor.py`
2. Use `public_ip_finder.py` for outbound rules
3. Use `private_ip_finder.py` for internal rules
4. CIDR consolidation reduces rule count

### **Network Documentation**
1. Clean asset list with `ip_extractor.py`
2. Analyze with `ip_counter.py` for inventory
3. Categorize with finder scripts
4. Export clean lists for documentation

### **Compliance Reporting**
1. Clean client data with `ip_extractor.py`
2. Count assets with `ip_counter.py`
3. Separate internal vs external with finder scripts
4. Generate clean reports

## Troubleshooting

### **Common Issues & Solutions**

**"File not found" error:**
- Check file path and spelling
- Use `dir` (Windows) or `ls` (Mac/Linux) to see files

**"No IPs found" error:**
- Verify file contains valid IP addresses
- Check file encoding (try opening in Notepad)
- Use `--verbose` flag for debugging

**"No public/private IPs found":**
- This usually means all IPs are the opposite type
- Use the other finder script instead
- Check your input file content

### **Getting Help**
- Run `python script_name.py --help` for detailed help
- Use `--verbose` flag to see what the script is doing
- Check that your input file contains valid IP addresses

## File Structure

```
IP_Address_Toolkit/
├── ip_extractor.py          # Clean & deduplicate IP lists
├── ip_counter.py            # Count & analyze IP addresses
├── public_ip_finder.py      # Extract external IPs only
├── private_ip_finder.py     # Extract internal IPs only
├── requirements.txt          # Python dependencies
├── capybara_ip_utility.bat  # Windows batch file utility
├── capybara_ip_utility.ps1  # Windows PowerShell utility
├── INSTALL.md               # Python installation guide
├── README.md                # This comprehensive guide
└── tests/                   # Test files and sample data
    ├── comprehensive_test.txt
    ├── overlap_test.txt
    ├── test_data.csv
    └── ... (other test files)
```

## Pro Tips

1. **Always start with `ip_extractor.py`** - Clean data first, then analyze
2. **Use descriptive filenames** - `client_name_clean.txt`, `client_name_external.txt`
3. **Save intermediate results** - Use `--output` to create new files
4. **Check output before using** - Verify results look correct
5. **Use `--detailed` first** - Understand what you're working with
6. **Keep original client files** - Never overwrite source data

## Dependencies

- **Python 3.6+** (included in most modern systems)
- **Optional:** `pandas` and `openpyxl` for Excel file support

## Installation

See `INSTALL.md` for detailed Python installation instructions.

## Windows Utility

For Windows users, two utility scripts are provided to simplify the workflow:

- **`capybara_ip_utility.bat`** - Batch file utility (double-click to run)
- **`capybara_ip_utility.ps1`** - PowerShell utility (run with `PowerShell -ExecutionPolicy Bypass -File .\capybara_ip_utility.ps1`)

**Requirements:**
- Python 3.6+ installed on the system
- Python executable in PATH or common installation locations
- Windows 10/11

**Setup:**
1. Ensure Python is installed (see `INSTALL.md`)
2. Place utility files in the same directory as Python scripts
3. Run the utility of your choice

The utility will automatically find Python and guide you through the complete workflow.

---

**Remember:** This toolkit is designed to handle messy input, so don't worry if your client's list looks terrible. Start with the extractor, then use the appropriate tools for your specific needs!
