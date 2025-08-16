# IP Address Extractor

A powerful Python script that parses various document formats and extracts IP addresses and ranges, converting them to standardized CIDR notation.

## Features

- **Multiple File Formats**: Supports CSV, Excel (.xlsx, .xls), JSON, and text files
- **IP Range Detection**: Automatically detects IP ranges (e.g., "192.168.1.1-192.168.1.100")
- **CIDR Conversion**: Converts IP ranges to efficient CIDR notation
- **Duplicate Removal**: Automatically removes duplicate IPs and ranges
- **Sorted Output**: Provides consistently sorted output for easy processing
- **Flexible Output**: Output to console or save to file

## Installation

### Basic Installation (Standard Library Only)
The script works with Python 3.6+ using only the standard library:

```bash
# No additional packages required for basic functionality
python ip_extractor.py --help
```

### Enhanced Installation (With Excel Support)
For Excel file support, install the optional dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
# Extract IPs from a CSV file
python ip_extractor.py data.csv

# Extract IPs from an Excel file
python ip_extractor.py spreadsheet.xlsx

# Extract IPs from a JSON file
python ip_extractor.py config.json

# Extract IPs from a text file
python ip_extractor.py logfile.txt
```

### Advanced Usage

```bash
# Save output to a file
python ip_extractor.py data.csv -o results.txt

# Verbose output with detailed information
python ip_extractor.py data.csv -v

# Combine options
python ip_extractor.py data.csv -o results.txt -v
```

### Command Line Options

- `file_path`: Path to the file to parse (required)
- `--output, -o`: Output file path (default: stdout)
- `--verbose, -v`: Verbose output with counts and details
- `--help, -h`: Show help message

## Examples

### Example 1: CSV File
```csv
name,ip_address,range
server1,192.168.1.10,192.168.1.1-192.168.1.100
server2,10.0.0.5,10.0.0.0/24
```

**Output:**
```
10.0.0.0/24, 10.0.0.5, 192.168.1.1, 192.168.1.10, 192.168.1.65/26, 192.168.1.97/27, 192.168.1.100
```

### Example 2: Text File
```
Network configuration:
- Gateway: 192.168.1.1
- DHCP range: 192.168.1.100 - 192.168.1.200
- DNS servers: 8.8.8.8, 8.8.4.4
- Subnet: 192.168.1.0/24
```

**Output:**
```
8.8.4.4, 8.8.8.8, 192.168.1.0/24, 192.168.1.1, 192.168.1.100/25, 192.168.1.200
```

### Example 3: JSON File
```json
{
  "servers": [
    {"name": "web1", "ip": "203.0.113.10"},
    {"name": "web2", "ip": "203.0.113.11"}
  ],
  "networks": [
    "203.0.113.0/24",
    "198.51.100.0/26"
  ]
}
```

**Output:**
```
198.51.100.0/26, 203.0.113.0/24, 203.0.113.10, 203.0.113.11
```

## How It Works

1. **File Detection**: Automatically detects file type based on extension
2. **Text Extraction**: Extracts all text content from the file
3. **IP Detection**: Uses regex patterns to find IP addresses and ranges
4. **Range Parsing**: Identifies IP ranges (e.g., "192.168.1.1-192.168.1.100")
5. **CIDR Conversion**: Converts ranges to efficient CIDR notation
6. **Deduplication**: Removes duplicate IPs and ranges
7. **Sorting**: Sorts output for consistency

## Supported IP Formats

### Individual IPs
- Standard IPv4: `192.168.1.1`
- Validated ranges: 0.0.0.0 to 255.255.255.255

### IP Ranges
- Dash notation: `192.168.1.1-192.168.1.100`
- CIDR notation: `192.168.1.0/24`

### Output Format
- Individual IPs: `192.168.1.1`
- CIDR ranges: `192.168.1.0/24` (excluding /32 which represent single IPs)
- Comma and space separated list: `192.168.1.1, 192.168.1.0/24, 10.0.0.5`

## Error Handling

The script gracefully handles:
- Missing files
- Corrupted files
- Unsupported formats
- Invalid IP addresses
- Encoding issues

## Performance

- **Small files** (< 1MB): Near-instant processing
- **Medium files** (1-100MB): Fast processing with memory-efficient parsing
- **Large files** (> 100MB): Stream-based processing to avoid memory issues

## Limitations

- Currently supports IPv4 addresses only
- Excel support requires pandas and openpyxl
- Very large files may take longer to process
- Complex nested structures in JSON may require flattening

## Troubleshooting

### Common Issues

1. **"pandas not available" warning**
   - Install with: `pip install pandas openpyxl`
   - Or ignore if you don't need Excel support

2. **Encoding errors**
   - The script uses UTF-8 with fallback
   - Most encoding issues are automatically handled

3. **Large file processing**
   - Use `-v` flag to monitor progress
   - Consider splitting very large files

### Getting Help

```bash
# Show help
python ip_extractor.py --help

# Check version
python --version

# Test with a simple file
echo "IP: 192.168.1.1" > test.txt
python ip_extractor.py test.txt
```

## Contributing

Feel free to submit issues, feature requests, or pull requests to improve the script.

## License

This script is provided as-is for educational and practical use.
