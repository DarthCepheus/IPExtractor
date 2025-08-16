#!/usr/bin/env python3
"""
IP Address Extractor

This script parses various document formats (CSV, Excel, text, JSON, etc.) and extracts
individual IP addresses and IP ranges, converting ranges to CIDR notation.
Output is formatted as a comma and space separated list, with /32 CIDR notation removed
since it represents single IP addresses.

Usage:
    python ip_extractor.py <file_path>
    python ip_extractor.py --help
"""

import argparse
import csv
import json
import re
import sys
from pathlib import Path
from typing import List, Set, Tuple, Union
import ipaddress
from collections import defaultdict

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

try:
    import openpyxl
    OPENPYXL_AVAILABLE = True
except ImportError:
    OPENPYXL_AVAILABLE = False


class IPExtractor:
    """Extract IP addresses and ranges from various document formats."""
    
    def __init__(self):
        # Regex patterns for IP addresses and ranges
        self.ip_pattern = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
        self.range_pattern = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\s*-\s*(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
        self.cidr_pattern = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-9]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:3[0-2]|[1-2][0-9]|[0-9])\b')
        
    def extract_ips_from_text(self, text: str) -> Tuple[Set[str], Set[str]]:
        """Extract individual IPs and ranges from text."""
        individual_ips = set()
        ip_ranges = set()
        
        # Extract individual IPs
        for match in self.ip_pattern.finditer(text):
            ip = match.group()
            # Check if it's not part of a range or CIDR
            if not self._is_part_of_range_or_cidr(text, match.start(), match.end()):
                individual_ips.add(ip)
        
        # Extract IP ranges
        for match in self.range_pattern.finditer(text):
            range_text = match.group()
            start_ip, end_ip = self._parse_ip_range(range_text)
            if start_ip and end_ip:
                cidr_ranges = self._convert_range_to_cidr(start_ip, end_ip)
                ip_ranges.update(cidr_ranges)
        
        # Extract existing CIDR notations
        for match in self.cidr_pattern.finditer(text):
            cidr = match.group()
            ip_ranges.add(cidr)
        
        return individual_ips, ip_ranges
    
    def _is_part_of_range_or_cidr(self, text: str, start: int, end: int) -> bool:
        """Check if an IP is part of a range or CIDR notation."""
        # Look for range indicators around the IP
        context_start = max(0, start - 20)
        context_end = min(len(text), end + 20)
        context = text[context_start:context_end]
        
        # Check for range indicators
        if '-' in context or '/' in context:
            return True
        return False
    
    def _parse_ip_range(self, range_text: str) -> Tuple[Union[str, None], Union[str, None]]:
        """Parse IP range text to get start and end IPs."""
        try:
            # Remove whitespace and split by dash
            clean_text = re.sub(r'\s+', '', range_text)
            if '-' in clean_text:
                start_ip, end_ip = clean_text.split('-', 1)
                # Validate both IPs
                if self._is_valid_ip(start_ip) and self._is_valid_ip(end_ip):
                    return start_ip, end_ip
        except Exception:
            pass
        return None, None
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if a string is a valid IP address."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _convert_range_to_cidr(self, start_ip: str, end_ip: str) -> Set[str]:
        """Convert IP range to CIDR notation."""
        try:
            start = ipaddress.IPv4Address(start_ip)
            end = ipaddress.IPv4Address(end_ip)
            
            if start > end:
                start, end = end, start
            
            cidr_ranges = set()
            
            # Generate CIDR blocks that cover the range
            current = start
            while current <= end:
                # Find the largest CIDR block starting at current
                for prefix_len in range(32, -1, -1):
                    try:
                        network = ipaddress.IPv4Network(f"{current}/{prefix_len}", strict=False)
                        if network.network_address == current and network.broadcast_address <= end:
                            # Don't add /32 networks - they represent single IPs
                            if prefix_len < 32:
                                cidr_ranges.add(str(network))
                            current = network.broadcast_address + 1
                            break
                    except ValueError:
                        continue
                else:
                    # If no CIDR block found, add as individual IP
                    cidr_ranges.add(str(current))
                    current += 1
            
            return cidr_ranges
            
        except Exception:
            return set()
    
    def parse_csv(self, file_path: str) -> Tuple[Set[str], Set[str]]:
        """Parse CSV file and extract IPs."""
        individual_ips = set()
        ip_ranges = set()
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                reader = csv.reader(file)
                for row in reader:
                    for cell in row:
                        ips, ranges = self.extract_ips_from_text(str(cell))
                        individual_ips.update(ips)
                        ip_ranges.update(ranges)
        except Exception as e:
            print(f"Error parsing CSV file: {e}", file=sys.stderr)
        
        return individual_ips, ip_ranges
    
    def parse_excel(self, file_path: str) -> Tuple[Set[str], Set[str]]:
        """Parse Excel file and extract IPs."""
        if not PANDAS_AVAILABLE:
            print("Warning: pandas not available, cannot parse Excel files", file=sys.stderr)
            return set(), set()
        
        individual_ips = set()
        ip_ranges = set()
        
        try:
            # Read all sheets
            excel_file = pd.ExcelFile(file_path)
            for sheet_name in excel_file.sheet_names:
                df = pd.read_excel(file_path, sheet_name=sheet_name)
                for column in df.columns:
                    for value in df[column].astype(str):
                        ips, ranges = self.extract_ips_from_text(str(value))
                        individual_ips.update(ips)
                        ip_ranges.update(ranges)
        except Exception as e:
            print(f"Error parsing Excel file: {e}", file=sys.stderr)
        
        return individual_ips, ip_ranges
    
    def parse_json(self, file_path: str) -> Tuple[Set[str], Set[str]]:
        """Parse JSON file and extract IPs."""
        individual_ips = set()
        ip_ranges = set()
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                data = json.load(file)
                json_text = json.dumps(data, default=str)
                ips, ranges = self.extract_ips_from_text(json_text)
                individual_ips.update(ips)
                ip_ranges.update(ranges)
        except Exception as e:
            print(f"Error parsing JSON file: {e}", file=sys.stderr)
        
        return individual_ips, ip_ranges
    
    def parse_text(self, file_path: str) -> Tuple[Set[str], Set[str]]:
        """Parse text file and extract IPs."""
        individual_ips = set()
        ip_ranges = set()
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                content = file.read()
                ips, ranges = self.extract_ips_from_text(content)
                individual_ips.update(ips)
                ip_ranges.update(ranges)
        except Exception as e:
            print(f"Error parsing text file: {e}", file=sys.stderr)
        
        return individual_ips, ip_ranges
    
    def parse_file(self, file_path: str) -> Tuple[Set[str], Set[str]]:
        """Parse file based on its extension."""
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        extension = file_path.suffix.lower()
        
        if extension == '.csv':
            return self.parse_csv(file_path)
        elif extension in ['.xlsx', '.xls']:
            return self.parse_excel(file_path)
        elif extension == '.json':
            return self.parse_json(file_path)
        else:
            # Try as text file for other extensions
            return self.parse_text(file_path)
    
    def format_output(self, individual_ips: Set[str], ip_ranges: Set[str]) -> str:
        """Format output as comma and space separated list."""
        # Process ranges to remove /32 (single IP addresses)
        processed_ranges = set()
        additional_ips = set()
        
        for cidr in ip_ranges:
            try:
                network = ipaddress.IPv4Network(cidr, strict=False)
                if network.prefixlen == 32:
                    # /32 means single IP, add to individual IPs instead
                    additional_ips.add(str(network.network_address))
                else:
                    processed_ranges.add(cidr)
            except ValueError:
                processed_ranges.add(cidr)
        
        # Combine all individual IPs
        all_individual_ips = individual_ips.union(additional_ips)
        
        # Sort IPs and ranges for consistent output
        sorted_ips = sorted(all_individual_ips, key=lambda ip: ipaddress.IPv4Address(ip))
        sorted_ranges = sorted(processed_ranges, key=lambda cidr: ipaddress.IPv4Network(cidr))
        
        # Combine and format with comma and space
        all_items = sorted_ips + sorted_ranges
        return ', '.join(all_items)


def main():
    parser = argparse.ArgumentParser(
        description="Extract IP addresses and ranges from various document formats",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ip_extractor.py document.csv
  python ip_extractor.py spreadsheet.xlsx
  python ip_extractor.py data.json
  python ip_extractor.py logfile.txt
        """
    )
    
    parser.add_argument(
        'file_path',
        help='Path to the file to parse'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Output file path (default: stdout)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output with counts and details'
    )
    
    args = parser.parse_args()
    
    try:
        extractor = IPExtractor()
        individual_ips, ip_ranges = extractor.parse_file(args.file_path)
        
        # Format output
        output_text = extractor.format_output(individual_ips, ip_ranges)
        
        # Write output
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output_text)
            print(f"Results written to: {args.output}")
        else:
            print(output_text)
        
        # Verbose output
        if args.verbose:
            print(f"\nSummary:", file=sys.stderr)
            print(f"Individual IPs found: {len(individual_ips)}", file=sys.stderr)
            print(f"IP ranges (CIDR) found: {len(ip_ranges)}", file=sys.stderr)
            print(f"Total items: {len(individual_ips) + len(ip_ranges)}", file=sys.stderr)
            
            if individual_ips:
                print(f"\nIndividual IPs:", file=sys.stderr)
                for ip in sorted(individual_ips, key=lambda ip: ipaddress.IPv4Address(ip)):
                    print(f"  {ip}", file=sys.stderr)
            
            if ip_ranges:
                print(f"\nIP Ranges (CIDR):", file=sys.stderr)
                for cidr in sorted(ip_ranges, key=lambda cidr: ipaddress.IPv4Network(cidr)):
                    print(f"  {cidr}", file=sys.stderr)
    
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
