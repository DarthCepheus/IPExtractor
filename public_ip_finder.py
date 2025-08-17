#!/usr/bin/env python3
"""
Public IP Finder - For New Users

This script takes a messy list of IP addresses from clients and:
1. Cleans up formatting issues (extra spaces, weird characters, etc.)
2. Identifies which IPs are PUBLIC (not private/internal)
3. Groups contiguous IPs into efficient CIDR ranges when possible
4. Outputs a clean, professional list ready for firewall rules or reports

WHAT IT DOES:
- Filters out private IPs (192.168.x.x, 10.x.x.x, etc.) 
- Keeps only public IPs (8.8.8.8, 203.0.113.x, etc.)
- Combines sequential IPs into CIDR blocks (192.168.1.1-3 becomes 192.168.1.0/30)
- Handles messy input files with encoding issues

USAGE EXAMPLES:
  # Basic usage - just give it a file
  python public_ip_finder.py client_ips.txt
  
  # Get detailed breakdown
  python public_ip_finder.py --detailed client_ips.txt
  
  # Save output to a file
  python public_ip_finder.py client_ips.txt --output clean_public_ips.txt
  
  # See what the script is doing (debug mode)
  python public_ip_finder.py client_ips.txt --verbose

INPUT FORMAT:
  The script accepts any of these:
  - Individual IPs: 8.8.8.8, 1.1.1.1
  - CIDR ranges: 203.0.113.0/24
  - Mixed: 8.8.8.8, 203.0.113.0/24, 1.1.1.1
  - Messy: 8.8.8.8 , 203.0.113.0/24 , 1.1.1.1

OUTPUT FORMAT:
  Clean, comma-separated list of public IPs and CIDR ranges
  Example: 8.8.8.8, 1.1.1.1, 203.0.113.0/24
"""

import argparse
import sys
import ipaddress
from typing import List, Set, Tuple
import re


class PublicIPFinder:
    """Filter and analyze public IP addresses from IP extractor output."""
    
    def __init__(self):
        # Private IP ranges (RFC 1918 and others)
        self.private_ranges = [
            ipaddress.IPv4Network('10.0.0.0/8'),      # Class A private
            ipaddress.IPv4Network('172.16.0.0/12'),   # Class B private
            ipaddress.IPv4Network('192.168.0.0/16'),  # Class C private
            ipaddress.IPv4Network('127.0.0.0/8'),     # Loopback
            ipaddress.IPv4Network('169.254.0.0/16'),  # Link-local
            ipaddress.IPv4Network('224.0.0.0/4'),     # Multicast
            ipaddress.IPv4Network('240.0.0.0/4'),     # Reserved
            ipaddress.IPv4Network('0.0.0.0/8'),       # Current network
            ipaddress.IPv4Network('100.64.0.0/10'),   # Carrier-grade NAT
        ]
    
    def is_public_ip(self, ip: ipaddress.IPv4Address) -> bool:
        """Check if an IP address is public (not private)."""
        for network in self.private_ranges:
            if ip in network:
                return False
        return True
    
    def expand_cidr_to_public_ips(self, cidr: str) -> Set[ipaddress.IPv4Address]:
        """Expand a CIDR notation to a set of public IP addresses only."""
        try:
            network = ipaddress.IPv4Network(cidr, strict=False)
            public_ips = set()
            
            for ip in network.hosts():
                if self.is_public_ip(ip):
                    public_ips.add(ip)
            
            return public_ips
        except ValueError:
            return set()
    
    def clean_input(self, ip_text: str) -> str:
        """Clean and normalize input text to handle common formatting issues."""
        if not ip_text:
            return ""
        
        # Remove BOM and null bytes
        # Remove UTF-16 BOM (ÿþ)
        cleaned = ip_text.replace('\ufeff', '').replace('\ufffe', '')
        
        # Remove null bytes
        cleaned = cleaned.replace('\x00', '')
        
        # Remove extra whitespace and normalize
        cleaned = cleaned.strip()
        
        # Handle common issues
        # Remove any trailing commas
        cleaned = cleaned.rstrip(',')
        
        # Normalize multiple spaces to single spaces
        cleaned = re.sub(r'\s+', ' ', cleaned)
        
        # Remove any empty items that might result from multiple commas
        items = [item.strip() for item in cleaned.split(',')]
        items = [item for item in items if item]
        
        return ', '.join(items)
    
    def parse_ip_list(self, ip_text: str) -> Tuple[Set[ipaddress.IPv4Address], Set[str]]:
        """Parse IP list and separate individual IPs from CIDR ranges."""
        individual_ips = set()
        cidr_ranges = set()
        
        # Split by comma and clean up
        items = [item.strip() for item in ip_text.split(',')]
        
        for item in items:
            if not item:
                continue
            
            # Clean up any extra whitespace or newlines
            item = item.strip()
            if not item:
                continue
                
            if '/' in item:
                # This might be a CIDR range - validate it
                try:
                    # Test if it's a valid CIDR notation
                    network = ipaddress.IPv4Network(item, strict=False)
                    cidr_ranges.add(item)
                except ValueError as e:
                    print(f"Warning: Invalid CIDR notation '{item}': {e}", file=sys.stderr)
                    # Try to extract just the IP part if possible
                    ip_part = item.split('/')[0].strip()
                    try:
                        ip = ipaddress.IPv4Address(ip_part)
                        individual_ips.add(ip)
                        print(f"  Extracted individual IP: {ip_part}", file=sys.stderr)
                    except ValueError:
                        print(f"  Could not extract valid IP from '{item}'", file=sys.stderr)
            else:
                # This is an individual IP
                try:
                    ip = ipaddress.IPv4Address(item)
                    individual_ips.add(ip)
                except ValueError as e:
                    print(f"Warning: Invalid IP address '{item}': {e}", file=sys.stderr)
        
        return individual_ips, cidr_ranges
    
    def find_public_ips(self, ip_text: str) -> dict:
        """Find all public IP addresses in the list."""
        individual_ips, cidr_ranges = self.parse_ip_list(ip_text)
        
        # Filter individual IPs for public ones
        public_individual_ips = set()
        for ip in individual_ips:
            if self.is_public_ip(ip):
                public_individual_ips.add(ip)
        
        # Analyze CIDR ranges for public IPs
        public_cidr_ranges = set()
        public_range_ips = set()
        range_stats = []
        
        for cidr in cidr_ranges:
            try:
                network = ipaddress.IPv4Network(cidr, strict=False)
                
                # Check if the entire range is public
                if self.is_public_ip(network.network_address) and self.is_public_ip(network.broadcast_address):
                    public_cidr_ranges.add(cidr)
                    range_ips = set(network.hosts())
                    public_range_ips.update(range_ips)
                    
                    range_stats.append({
                        'cidr': cidr,
                        'type': 'fully_public',
                        'total_ips': len(range_ips),
                        'public_ips': len(range_ips)
                    })
                
                # Check if range contains any public IPs
                else:
                    public_ips_in_range = self.expand_cidr_to_public_ips(cidr)
                    if public_ips_in_range:
                        public_range_ips.update(public_ips_in_range)
                        
                        range_stats.append({
                            'cidr': cidr,
                            'type': 'mixed',
                            'total_ips': len(set(network.hosts())),
                            'public_ips': len(public_ips_in_range)
                        })
                
            except ValueError as e:
                print(f"Warning: Invalid CIDR '{cidr}': {e}", file=sys.stderr)
                # Try to extract individual IPs from the malformed CIDR
                try:
                    ip_part = cidr.split('/')[0].strip()
                    ip = ipaddress.IPv4Address(ip_part)
                    if self.is_public_ip(ip):
                        public_range_ips.add(ip)
                        print(f"  Extracted public IP: {ip_part}", file=sys.stderr)
                except (ValueError, IndexError):
                    print(f"  Could not extract valid IP from malformed CIDR '{cidr}'", file=sys.stderr)
        
        return {
            'individual_public_ips': sorted(public_individual_ips, key=lambda ip: ipaddress.IPv4Address(ip)),
            'public_cidr_ranges': sorted(public_cidr_ranges, key=lambda cidr: ipaddress.IPv4Network(cidr)),
            'public_range_ips': sorted(public_range_ips, key=lambda ip: ipaddress.IPv4Address(ip)),
            'range_analysis': range_stats,
            'summary': {
                'total_public_ips': len(public_individual_ips) + len(public_range_ips),
                'individual_public_ips': len(public_individual_ips),
                'public_ips_in_ranges': len(public_range_ips),
                'fully_public_ranges': len([r for r in range_stats if r['type'] == 'fully_public']),
                'mixed_ranges': len([r for r in range_stats if r['type'] == 'mixed'])
            }
        }
    
    def consolidate_ips_to_cidr(self, ip_addresses: Set[ipaddress.IPv4Address]) -> List[str]:
        """Consolidate contiguous IP addresses back into CIDR ranges when possible."""
        if not ip_addresses:
            return []
        
        # Convert to sorted list
        sorted_ips = sorted(ip_addresses, key=lambda ip: int(ip))
        
        consolidated = []
        start_ip = sorted_ips[0]
        prev_ip = start_ip
        
        for current_ip in sorted_ips[1:]:
            # Check if this IP is contiguous with the previous one
            if int(current_ip) == int(prev_ip) + 1:
                # Continue the range
                prev_ip = current_ip
            else:
                # End of current range, add it to results
                if start_ip == prev_ip:
                    # Single IP
                    consolidated.append(str(start_ip))
                else:
                    # Range - find the best CIDR representation
                    cidr = self._find_best_cidr(start_ip, prev_ip)
                    consolidated.append(cidr)
                
                # Start new range
                start_ip = current_ip
                prev_ip = current_ip
        
        # Handle the last range
        if start_ip == prev_ip:
            # Single IP
            consolidated.append(str(start_ip))
        else:
            # Range - find the best CIDR representation
            cidr = self._find_best_cidr(start_ip, prev_ip)
            consolidated.append(cidr)
        
        return consolidated
    
    def _find_best_cidr(self, start_ip: ipaddress.IPv4Address, end_ip: ipaddress.IPv4Address) -> str:
        """Find the most efficient CIDR representation for a range of IPs."""
        # Try to find the largest CIDR block that covers the range
        for prefix_len in range(32, -1, -1):
            try:
                network = ipaddress.IPv4Network(f"{start_ip}/{prefix_len}", strict=False)
                if (network.network_address <= start_ip and 
                    network.broadcast_address >= end_ip):
                    return str(network)
            except ValueError:
                continue
        
        # If no CIDR found, return as individual IPs
        return f"{start_ip}, {end_ip}"
    
    def format_output(self, public_ips_data: dict, detailed: bool = False) -> str:
        """Format the output as a comma-separated list or detailed report."""
        if detailed:
            return self._format_detailed(public_ips_data)
        else:
            return self._format_simple(public_ips_data)
    
    def _format_simple(self, public_ips_data: dict) -> str:
        """Format as simple comma-separated list with CIDR consolidation."""
        all_public_items = []
        
        # Add individual public IPs
        if public_ips_data['individual_public_ips']:
            consolidated_individual = self.consolidate_ips_to_cidr(public_ips_data['individual_public_ips'])
            all_public_items.extend(consolidated_individual)
        
        # Add public IPs from ranges
        if public_ips_data['public_range_ips']:
            consolidated_ranges = self.consolidate_ips_to_cidr(public_ips_data['public_range_ips'])
            all_public_items.extend(consolidated_ranges)
        
        return ', '.join(all_public_items)
    
    def _format_detailed(self, public_ips_data: dict) -> str:
        """Format as detailed report."""
        lines = []
        lines.append("Public IP Address Analysis")
        lines.append("=" * 50)
        lines.append("")
        
        # Summary
        lines.append("Summary:")
        lines.append(f"  Total Public IPs: {public_ips_data['summary']['total_public_ips']}")
        lines.append(f"  Individual Public IPs: {public_ips_data['summary']['individual_public_ips']}")
        lines.append(f"  Public IPs in Ranges: {public_ips_data['summary']['public_ips_in_ranges']}")
        lines.append(f"  Fully Public Ranges: {public_ips_data['summary']['fully_public_ranges']}")
        lines.append(f"  Mixed Ranges: {public_ips_data['summary']['mixed_ranges']}")
        lines.append("")
        
        # Individual public IPs
        if public_ips_data['individual_public_ips']:
            lines.append("Individual Public IPs:")
            for ip in public_ips_data['individual_public_ips']:
                lines.append(f"  {ip}")
            lines.append("")
        
        # Public CIDR ranges
        if public_ips_data['public_cidr_ranges']:
            lines.append("Fully Public CIDR Ranges:")
            for cidr in public_ips_data['public_cidr_ranges']:
                lines.append(f"  {cidr}")
            lines.append("")
        
        # Range analysis
        if public_ips_data['range_analysis']:
            lines.append("Range Analysis:")
            for range_info in public_ips_data['range_analysis']:
                if range_info['type'] == 'fully_public':
                    lines.append(f"  {range_info['cidr']}: {range_info['public_ips']} public IPs (fully public)")
                else:
                    lines.append(f"  {range_info['cidr']}: {range_info['public_ips']} public IPs out of {range_info['total_ips']} total")
            lines.append("")
        
        # Simple list
        lines.append("All Public IPs (comma-separated):")
        lines.append(self._format_simple(public_ips_data))
        
        return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Clean up messy IP lists and extract only PUBLIC IP addresses",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
QUICK START FOR NEW USERS:
  1. Save your client's IP list to a text file (e.g., client_ips.txt)
  2. Run: python public_ip_finder.py client_ips.txt
  3. Copy the clean output for your firewall rules or reports

EXAMPLES:
  # Basic cleanup
  python public_ip_finder.py client_ips.txt
  
  # Get detailed breakdown (shows what was found)
  python public_ip_finder.py --detailed client_ips.txt
  
  # Save clean results to a new file
  python public_ip_finder.py client_ips.txt --output clean_ips.txt
  
  # Debug mode (see what the script is cleaning up)
  python public_ip_finder.py client_ips.txt --verbose

TROUBLESHOOTING:
  - If you get errors, try the --verbose flag to see what's happening
  - The script automatically handles most formatting issues
  - If it still fails, check that your file contains valid IP addresses
        """
    )
    
    parser.add_argument(
        'file_path',
        nargs='?',
        help='Path to your text file containing the IP list (REQUIRED)'
    )
    
    parser.add_argument(
        '--detailed', '-d',
        action='store_true',
        help='Show detailed breakdown - useful for understanding what was found'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show debug info - use this if something goes wrong'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Save results to a file instead of printing to screen'
    )
    
    args = parser.parse_args()
    
    try:
        # Read IP list
        if args.file_path:
            try:
                # Try to read with UTF-8 first
                with open(args.file_path, 'r', encoding='utf-8') as f:
                    ip_text = f.read().strip()
            except UnicodeDecodeError:
                try:
                    # Try UTF-16 if UTF-8 fails
                    with open(args.file_path, 'r', encoding='utf-16') as f:
                        ip_text = f.read().strip()
                except UnicodeDecodeError:
                    # Try with system default encoding
                    with open(args.file_path, 'r', encoding='cp1252') as f:
                        ip_text = f.read().strip()
        else:
            print("ERROR: You must provide a file path!", file=sys.stderr)
            print("", file=sys.stderr)
            print("USAGE: python public_ip_finder.py your_file.txt", file=sys.stderr)
            print("", file=sys.stderr)
            print("For help: python public_ip_finder.py --help", file=sys.stderr)
            sys.exit(1)
        
        if not ip_text:
            print("ERROR: The file appears to be empty!", file=sys.stderr)
            print("", file=sys.stderr)
            print("Please check that your file contains IP addresses.", file=sys.stderr)
            print("Example content: 8.8.8.8, 1.1.1.1, 203.0.113.0/24", file=sys.stderr)
            sys.exit(1)
        
        # Clean and normalize input
        finder = PublicIPFinder()
        cleaned_ip_text = finder.clean_input(ip_text)
        
        if not cleaned_ip_text:
            print("ERROR: No valid IP addresses found after cleaning!", file=sys.stderr)
            print("", file=sys.stderr)
            print("This usually means the file doesn't contain valid IP addresses.", file=sys.stderr)
            print("Try the --verbose flag to see what the script found: python public_ip_finder.py --verbose your_file.txt", file=sys.stderr)
            sys.exit(1)
        
        # Debug: Show what was cleaned (only if verbose)
        if args.verbose and args.file_path and len(cleaned_ip_text) != len(ip_text):
            print(f"Note: Input cleaned from {len(ip_text)} to {len(cleaned_ip_text)} characters", file=sys.stderr)
            if args.verbose:
                print(f"Original: {repr(ip_text[:100])}...", file=sys.stderr)
                print(f"Cleaned:  {repr(cleaned_ip_text[:100])}...", file=sys.stderr)
        
        # Find public IPs
        public_ips_data = finder.find_public_ips(cleaned_ip_text)
        
        # Check if we found any public IPs
        if public_ips_data['summary']['total_public_ips'] == 0:
            print("NOTE: No public IP addresses found in your list.", file=sys.stderr)
            print("", file=sys.stderr)
            print("This usually means all IPs are private/internal (192.168.x.x, 10.x.x.x, etc.)", file=sys.stderr)
            print("If you expected public IPs, check your input file.", file=sys.stderr)
            print("", file=sys.stderr)
            print("Try the --detailed flag to see what was found: python public_ip_finder.py --detailed your_file.txt", file=sys.stderr)
            sys.exit(0)
        
        # Format output
        output_text = finder.format_output(public_ips_data, args.detailed)
        
        # Write output
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output_text)
            print(f"SUCCESS: Clean public IPs saved to: {args.output}")
            print(f"Found {public_ips_data['summary']['total_public_ips']} public IP addresses")
        else:
            print(output_text)
    
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
