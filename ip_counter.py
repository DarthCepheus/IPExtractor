#!/usr/bin/env python3
"""
IP Counter and Analyzer

This script analyzes the output from the IP extractor script and provides:
- Total count of individual IPs
- Count of public IPs
- Count of private IPs

Usage:
    python ip_counter.py <ip_list_file>
    python ip_counter.py --help
    echo "192.168.1.1, 10.0.0.0/24" | python ip_counter.py
"""

import argparse
import sys
import ipaddress
from typing import List, Set, Tuple


class IPCounter:
    """Count and categorize IP addresses from IP extractor output."""
    
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
    
    def is_private_ip(self, ip: ipaddress.IPv4Address) -> bool:
        """Check if an IP address is private."""
        for network in self.private_ranges:
            if ip in network:
                return True
        return False
    
    def expand_cidr_to_ips(self, cidr: str) -> Set[ipaddress.IPv4Address]:
        """Expand a CIDR notation to a set of individual IP addresses."""
        try:
            network = ipaddress.IPv4Network(cidr, strict=False)
            return set(network.hosts())
        except ValueError:
            return set()
    
    def parse_ip_list(self, ip_text: str) -> Tuple[Set[ipaddress.IPv4Address], Set[ipaddress.IPv4Address]]:
        """Parse IP list and separate individual IPs from CIDR ranges."""
        individual_ips = set()
        cidr_ranges = set()
        
        # Split by comma and clean up
        items = [item.strip() for item in ip_text.split(',')]
        
        for item in items:
            if not item:
                continue
                
            if '/' in item:
                # This is a CIDR range
                cidr_ranges.add(item)
            else:
                # This is an individual IP
                try:
                    ip = ipaddress.IPv4Address(item)
                    individual_ips.add(ip)
                except ValueError:
                    print(f"Warning: Invalid IP address '{item}'", file=sys.stderr)
        
        return individual_ips, cidr_ranges
    
    def count_all_ips(self, ip_text: str) -> Tuple[int, int, int]:
        """Count total, public, and private IPs."""
        individual_ips, cidr_ranges = self.parse_ip_list(ip_text)
        
        # Count individual IPs
        total_count = len(individual_ips)
        public_count = 0
        private_count = 0
        
        for ip in individual_ips:
            if self.is_private_ip(ip):
                private_count += 1
            else:
                public_count += 1
        
        # Expand CIDR ranges and count
        for cidr in cidr_ranges:
            range_ips = self.expand_cidr_to_ips(cidr)
            total_count += len(range_ips)
            
            for ip in range_ips:
                if self.is_private_ip(ip):
                    private_count += 1
                else:
                    public_count += 1
        
        return total_count, public_count, private_count
    
    def analyze_ip_list(self, ip_text: str) -> dict:
        """Analyze IP list and return detailed statistics."""
        individual_ips, cidr_ranges = self.parse_ip_list(ip_text)
        
        # Count individual IPs
        individual_public = 0
        individual_private = 0
        
        for ip in individual_ips:
            if self.is_private_ip(ip):
                individual_private += 1
            else:
                individual_public += 1
        
        # Analyze CIDR ranges
        range_stats = []
        range_public = 0
        range_private = 0
        
        for cidr in cidr_ranges:
            try:
                network = ipaddress.IPv4Network(cidr, strict=False)
                range_ips = set(network.hosts())
                range_count = len(range_ips)
                
                # Count public vs private in this range
                range_pub = 0
                range_priv = 0
                for ip in range_ips:
                    if self.is_private_ip(ip):
                        range_priv += 1
                    else:
                        range_pub += 1
                
                range_stats.append({
                    'cidr': cidr,
                    'total_ips': range_count,
                    'public_ips': range_pub,
                    'private_ips': range_priv
                })
                
                range_public += range_pub
                range_private += range_priv
                
            except ValueError:
                print(f"Warning: Invalid CIDR '{cidr}'", file=sys.stderr)
        
        return {
            'individual_ips': {
                'total': len(individual_ips),
                'public': individual_public,
                'private': individual_private
            },
            'cidr_ranges': {
                'total_ranges': len(cidr_ranges),
                'total_ips': range_public + range_private,
                'public_ips': range_public,
                'private_ips': range_private,
                'ranges': range_stats
            },
            'summary': {
                'total_ips': len(individual_ips) + range_public + range_private,
                'public_ips': individual_public + range_public,
                'private_ips': individual_private + range_private
            }
        }


def main():
    parser = argparse.ArgumentParser(
        description="Count and categorize IP addresses from IP extractor output",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ip_counter.py ip_list.txt
  python ip_counter.py --detailed ip_list.txt
  echo "192.168.1.1, 10.0.0.0/24" | python ip_counter.py
        """
    )
    
    parser.add_argument(
        'file_path',
        nargs='?',
        help='Path to file containing IP list (or read from stdin)'
    )
    
    parser.add_argument(
        '--detailed', '-d',
        action='store_true',
        help='Show detailed breakdown of IPs and ranges'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Output file path (default: stdout)'
    )
    
    args = parser.parse_args()
    
    try:
        # Read IP list
        if args.file_path:
            with open(args.file_path, 'r') as f:
                ip_text = f.read().strip()
        else:
            # Read from stdin
            ip_text = sys.stdin.read().strip()
        
        if not ip_text:
            print("Error: No IP addresses found", file=sys.stderr)
            sys.exit(1)
        
        # Analyze IPs
        counter = IPCounter()
        analysis = counter.analyze_ip_list(ip_text)
        
        # Prepare output
        output_lines = []
        
        if args.detailed:
            # Detailed output
            output_lines.append("IP Address Analysis")
            output_lines.append("=" * 50)
            output_lines.append("")
            
            # Individual IPs
            output_lines.append("Individual IP Addresses:")
            output_lines.append(f"  Total: {analysis['individual_ips']['total']}")
            output_lines.append(f"  Public: {analysis['individual_ips']['public']}")
            output_lines.append(f"  Private: {analysis['individual_ips']['private']}")
            output_lines.append("")
            
            # CIDR Ranges
            output_lines.append("CIDR Ranges:")
            output_lines.append(f"  Total Ranges: {analysis['cidr_ranges']['total_ranges']}")
            output_lines.append(f"  Total IPs in Ranges: {analysis['cidr_ranges']['total_ips']}")
            output_lines.append(f"  Public IPs in Ranges: {analysis['cidr_ranges']['public_ips']}")
            output_lines.append(f"  Private IPs in Ranges: {analysis['cidr_ranges']['private_ips']}")
            output_lines.append("")
            
            # Range details
            if analysis['cidr_ranges']['ranges']:
                output_lines.append("Range Details:")
                for range_info in analysis['cidr_ranges']['ranges']:
                    output_lines.append(f"  {range_info['cidr']}: {range_info['total_ips']} IPs "
                                     f"({range_info['public_ips']} public, {range_info['private_ips']} private)")
                output_lines.append("")
            
            # Summary
            output_lines.append("Summary:")
            output_lines.append(f"  Total IPs: {analysis['summary']['total_ips']}")
            output_lines.append(f"  Public IPs: {analysis['summary']['public_ips']}")
            output_lines.append(f"  Private IPs: {analysis['summary']['private_ips']}")
            
        else:
            # Simple output
            output_lines.append(f"Total IPs: {analysis['summary']['total_ips']}")
            output_lines.append(f"Public IPs: {analysis['summary']['public_ips']}")
            output_lines.append(f"Private IPs: {analysis['summary']['private_ips']}")
        
        output_text = '\n'.join(output_lines)
        
        # Write output
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output_text)
            print(f"Results written to: {args.output}")
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
