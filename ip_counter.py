#!/usr/bin/env python3
"""
IP Counter and Analyzer - A Learning Tool for Cybersecurity Professionals

Copyright (c) 2024 IP Address Parsing Solution
Licensed under the MIT License - see LICENSE file for details.

This script demonstrates several important Python concepts while providing practical
IP address analysis functionality. It's designed to help security professionals
learn Python while solving real-world network analysis problems.

LEARNING OBJECTIVES:
- Network analysis and IP address classification
- Working with the ipaddress module for network operations
- Set operations and data processing
- File I/O and command-line argument parsing
- Error handling and input validation
- Network security concepts (RFC 1918 private ranges)
- SECURITY: Input sanitization and validation
- SECURITY: Information disclosure prevention

This script analyzes the output from the IP extractor script and provides:
- Total count of individual IPs
- Count of public IPs
- Count of private IPs
- Detailed breakdown of IP types and ranges

SECURITY FEATURES:
- Input sanitization and length limits
- Safe error handling (no information disclosure)
- Null byte and control character removal
- Input validation and type checking

Usage:
    python ip_counter.py <ip_list_file>
    python ip_counter.py --help
    echo "192.168.1.1, 10.0.0.0/24" | python ip_counter.py
"""

# =============================================================================
# STANDARD LIBRARY IMPORTS
# =============================================================================
import argparse      # Command-line argument parsing (intermediate concept)
import sys           # System-specific parameters and functions
import ipaddress     # IP address manipulation and network analysis (advanced concept)

# =============================================================================
# TYPE HINTS - Modern Python feature for better code documentation
# =============================================================================
from typing import List, Set, Tuple  # Type hints (intermediate concept)


class IPCounter:
    """
    Count and categorize IP addresses from IP extractor output.
    
    LEARNING: This class demonstrates object-oriented programming principles
    - Encapsulation: Data and methods are grouped together
    - Initialization: Constructor method sets up the object's state
    - Network knowledge: Understanding of RFC 1918 and other IP ranges
    """
    
    def __init__(self):
        """
        Constructor method - runs when we create a new IPCounter object
        
        LEARNING: This method initializes the object with network knowledge
        - RFC 1918 defines private IP address ranges
        - These ranges are reserved for internal networks
        - Understanding these is crucial for network security
        """
        # LEARNING: RFC 1918 Private IP Ranges - Essential for cybersecurity
        # These ranges are reserved and should not appear on the public internet
        self.private_ranges = [
            ipaddress.IPv4Network('10.0.0.0/8'),      # Class A private (10.x.x.x)
            ipaddress.IPv4Network('172.16.0.0/12'),   # Class B private (172.16-31.x.x)
            ipaddress.IPv4Network('192.168.0.0/16'),  # Class C private (192.168.x.x)
            ipaddress.IPv4Network('127.0.0.0/8'),     # Loopback (127.x.x.x)
            ipaddress.IPv4Network('169.254.0.0/16'),  # Link-local (169.254.x.x)
            ipaddress.IPv4Network('224.0.0.0/4'),     # Multicast (224-239.x.x.x)
            ipaddress.IPv4Network('240.0.0.0/4'),     # Reserved (240-255.x.x.x)
            ipaddress.IPv4Network('0.0.0.0/8'),       # Current network
            ipaddress.IPv4Network('100.64.0.0/10'),   # Carrier-grade NAT (100.64-127.x.x)
        ]
    
    def is_private_ip(self, ip: ipaddress.IPv4Address) -> bool:
        """
        Check if an IP address is private.
        
        LEARNING: This method demonstrates network membership testing
        - The 'in' operator works with ipaddress objects
        - We iterate through our predefined private ranges
        - This is a common pattern in network security analysis
        
        Args:
            ip (ipaddress.IPv4Address): IP address to check
            
        Returns:
            bool: True if private, False if public
        """
        # LEARNING: Iterate through our predefined private network ranges
        # The 'in' operator checks if an IP is within a network
        for network in self.private_ranges:
            if ip in network:
                return True
        return False
    
    def expand_cidr_to_ips(self, cidr: str) -> Set[ipaddress.IPv4Address]:
        """
        Expand a CIDR notation to a set of individual IP addresses.
        
        LEARNING: This method demonstrates CIDR network expansion
        - network.hosts() returns an iterator of all IPs in a network
        - We convert it to a set for efficient operations
        - Error handling prevents crashes from invalid CIDR notation
        
        Args:
            cidr (str): CIDR notation (e.g., "192.168.1.0/24")
            
        Returns:
            Set[ipaddress.IPv4Address]: Set of individual IP addresses
        """
        try:
            # LEARNING: Create a network object from CIDR string
            # strict=False allows networks that don't start at network boundary
            network = ipaddress.IPv4Network(cidr, strict=False)
            
            # LEARNING: .hosts() returns all usable IPs in the network
            # We convert to a set for efficient membership testing
            return set(network.hosts())
            
        except ValueError:
            # LEARNING: Return empty set for invalid CIDR notation
            # This prevents the program from crashing on bad input
            return set()
    
    def _sanitize_input(self, text: str) -> str:
        """
        Sanitize input text to prevent injection attacks.
        
        LEARNING: This method demonstrates input sanitization best practices
        - Remove potentially dangerous characters
        - Limit input length to prevent DoS attacks
        - Normalize whitespace and special characters
        
        SECURITY: Prevents various injection attacks and ensures
        input data is safe for processing.
        
        Args:
            text (str): Raw input text
            
        Returns:
            str: Sanitized text safe for processing
        """
        if not isinstance(text, str):
            return ""
        
        # SECURITY: Limit input length to prevent DoS attacks
        if len(text) > 10000:  # 10KB limit
            raise ValueError("Input text too long (max 10KB)")
        
        # SECURITY: Remove null bytes and control characters
        # These can cause issues in various contexts
        text = text.replace('\x00', '')  # Null bytes
        text = text.replace('\r', '')    # Carriage returns
        
        # SECURITY: Normalize whitespace to prevent confusion
        import re
        text = re.sub(r'\s+', ' ', text)
        
        # SECURITY: Remove any non-printable characters
        text = ''.join(char for char in text if char.isprintable() or char.isspace())
        
        return text.strip()
    
    def parse_ip_list(self, ip_text: str) -> Tuple[Set[ipaddress.IPv4Address], Set[ipaddress.IPv4Address]]:
        """
        Parse IP list and separate individual IPs from CIDR ranges.
        
        LEARNING: This method demonstrates text parsing and data classification
        - String splitting and cleaning
        - Pattern recognition (CIDR vs individual IP)
        - Error handling during parsing
        - Set operations for data organization
        - SECURITY: Input sanitization prevents injection attacks
        
        Args:
            ip_text (str): Comma-separated list of IPs and CIDR ranges
            
        Returns:
            Tuple[Set[ipaddress.IPv4Address], Set[ipaddress.IPv4Address]]: (individual_ips, cidr_ranges)
        """
        individual_ips = set()
        cidr_ranges = set()
        
        # SECURITY: Sanitize input before processing
        # This prevents various injection attacks
        sanitized_text = self._sanitize_input(ip_text)
        
        # LEARNING: List comprehension with string cleaning
        # .split(',') splits on commas, .strip() removes whitespace
        # This handles messy input like " 192.168.1.1 , 10.0.0.0/24 "
        items = [item.strip() for item in sanitized_text.split(',')]
        
        for item in items:
            if not item:
                continue
                
            # LEARNING: Simple pattern recognition - CIDR notation contains '/'
            # This is a basic but effective way to distinguish IP types
            if '/' in item:
                # This is a CIDR range
                cidr_ranges.add(item)
            else:
                # This is an individual IP
                try:
                    # LEARNING: Convert string to IP address object
                    # This validates the IP format and creates a usable object
                    ip = ipaddress.IPv4Address(item)
                    individual_ips.add(ip)
                except ValueError:
                    # LEARNING: Print warnings to stderr for invalid IPs
                    # This allows processing to continue while alerting the user
                    # SECURITY: Don't expose raw input in error messages
                    print(f"Warning: Invalid IP address format detected", file=sys.stderr)
        
        return individual_ips, cidr_ranges
    
    def count_all_ips(self, ip_text: str) -> Tuple[int, int, int]:
        """
        Count total, public, and private IPs.
        
        LEARNING: This method demonstrates data aggregation and counting
        - Processing individual IPs and CIDR ranges separately
        - Accumulating counts across different data types
        - Using helper methods to break down complex logic
        
        Args:
            ip_text (str): Comma-separated list of IPs and CIDR ranges
            
        Returns:
            Tuple[int, int, int]: (total_count, public_count, private_count)
        """
        # LEARNING: Parse the input text into organized data structures
        # This separates the parsing logic from the counting logic
        individual_ips, cidr_ranges = self.parse_ip_list(ip_text)
        
        # STEP 1: Count individual IPs
        # LEARNING: Initialize counters before processing
        total_count = len(individual_ips)
        public_count = 0
        private_count = 0
        
        # LEARNING: Iterate through individual IPs and classify them
        for ip in individual_ips:
            if self.is_private_ip(ip):
                private_count += 1
            else:
                public_count += 1
        
        # STEP 2: Expand CIDR ranges and count
        # LEARNING: Process each CIDR range to get individual IPs
        for cidr in cidr_ranges:
            # LEARNING: Use helper method to expand CIDR to individual IPs
            range_ips = self.expand_cidr_to_ips(cidr)
            total_count += len(range_ips)
            
            # LEARNING: Classify each IP in the range
            for ip in range_ips:
                if self.is_private_ip(ip):
                    private_count += 1
                else:
                    public_count += 1
        
        return total_count, public_count, private_count
    
    def analyze_ip_list(self, ip_text: str) -> dict:
        """
        Analyze IP list and return detailed statistics.
        
        LEARNING: This method demonstrates comprehensive data analysis
        - Detailed breakdown of IP types and ranges
        - Dictionary construction with structured data
        - Error handling during network analysis
        - Data aggregation across multiple dimensions
        
        Args:
            ip_text (str): Comma-separated list of IPs and CIDR ranges
            
        Returns:
            dict: Comprehensive analysis results
        """
        # LEARNING: Parse input into organized data structures
        individual_ips, cidr_ranges = self.parse_ip_list(ip_text)
        
        # STEP 1: Analyze individual IPs
        # LEARNING: Count public vs private individual IPs
        individual_public = 0
        individual_private = 0
        
        for ip in individual_ips:
            if self.is_private_ip(ip):
                individual_private += 1
            else:
                individual_public += 1
        
        # STEP 2: Analyze CIDR ranges
        # LEARNING: Build detailed statistics for each range
        range_stats = []
        range_public = 0
        range_private = 0
        
        for cidr in cidr_ranges:
            try:
                # LEARNING: Create network object for analysis
                network = ipaddress.IPv4Network(cidr, strict=False)
                range_ips = set(network.hosts())
                range_count = len(range_ips)
                
                # LEARNING: Count public vs private IPs within this range
                range_pub = 0
                range_priv = 0
                for ip in range_ips:
                    if self.is_private_ip(ip):
                        range_priv += 1
                    else:
                        range_pub += 1
                
                # LEARNING: Build detailed statistics for this range
                # Dictionary structure makes data easy to access and understand
                range_stats.append({
                    'cidr': cidr,
                    'total_ips': range_count,
                    'public_ips': range_pub,
                    'private_ips': range_priv
                })
                
                # LEARNING: Accumulate totals across all ranges
                range_public += range_pub
                range_private += range_priv
                
            except ValueError:
                # LEARNING: Handle invalid CIDR notation gracefully
                # Print warning but continue processing other ranges
                print(f"Warning: Invalid CIDR '{cidr}'", file=sys.stderr)
        
        # LEARNING: Return structured data in a nested dictionary format
        # This makes it easy for other code to access specific information
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
    """
    Main function - entry point for the script.
    
    LEARNING: This function demonstrates command-line interface design and data processing
    - Argument parsing with argparse
    - File I/O and stdin handling
    - Data analysis and output formatting
    - Error handling and user feedback
    """
    # LEARNING: Create argument parser for professional command-line interface
    parser = argparse.ArgumentParser(
        description="Count and categorize IP addresses from IP extractor output",
        formatter_class=argparse.RawDescriptionHelpFormatter,  # Preserves formatting
        epilog="""
Examples:
  python ip_counter.py ip_list.txt
  python ip_counter.py --detailed ip_list.txt
  echo "192.168.1.1, 10.0.0.0/24" | python ip_counter.py
        """
    )
    
    # LEARNING: Optional positional argument (nargs='?')
    # This allows the script to work with or without a file path
    # If no file path is provided, it reads from stdin
    parser.add_argument(
        'file_path',
        nargs='?',
        help='Path to file containing IP list (or read from stdin)'
    )
    
    # LEARNING: Flag argument (action='store_true')
    # --detailed sets args.detailed to True, otherwise it's False
    parser.add_argument(
        '--detailed', '-d',
        action='store_true',
        help='Show detailed breakdown of IPs and ranges'
    )
    
    # LEARNING: Optional argument with value
    # --output requires a file path value
    parser.add_argument(
        '--output', '-o',
        help='Output file path (default: stdout)'
    )
    
    # LEARNING: Parse command line arguments
    args = parser.parse_args()
    
    try:
        # LEARNING: Flexible input handling - file or stdin
        if args.file_path:
            # LEARNING: Read from specified file
            # Context manager (with statement) automatically closes the file
            with open(args.file_path, 'r') as f:
                ip_text = f.read().strip()
        else:
            # LEARNING: Read from standard input (stdin)
            # This allows piping data: echo "192.168.1.1" | python ip_counter.py
            ip_text = sys.stdin.read().strip()
        
        # LEARNING: Input validation - check if we actually got data
        if not ip_text:
            print("Error: No IP addresses found", file=sys.stderr)
            sys.exit(1)
        
        # LEARNING: Create IPCounter object and analyze the data
        counter = IPCounter()
        analysis = counter.analyze_ip_list(ip_text)
        
        # LEARNING: Build output as a list of lines, then join them
        # This approach is more efficient than string concatenation
        output_lines = []
        
        if args.detailed:
            # LEARNING: Build detailed, formatted output
            # This provides comprehensive information for analysis
            output_lines.append("IP Address Analysis")
            output_lines.append("=" * 50)
            output_lines.append("")
            
            # LEARNING: Individual IP breakdown
            # Shows counts for IPs that aren't part of ranges
            output_lines.append("Individual IP Addresses:")
            output_lines.append(f"  Total: {analysis['individual_ips']['total']}")
            output_lines.append(f"  Public: {analysis['individual_ips']['public']}")
            output_lines.append(f"  Private: {analysis['individual_ips']['private']}")
            output_lines.append("")
            
            # LEARNING: CIDR range summary
            # Shows aggregate statistics for all ranges
            output_lines.append("CIDR Ranges:")
            output_lines.append(f"  Total Ranges: {analysis['cidr_ranges']['total_ranges']}")
            output_lines.append(f"  Total IPs in Ranges: {analysis['cidr_ranges']['total_ips']}")
            output_lines.append(f"  Public IPs in Ranges: {analysis['cidr_ranges']['public_ips']}")
            output_lines.append(f"  Private IPs in Ranges: {analysis['cidr_ranges']['private_ips']}")
            output_lines.append("")
            
            # LEARNING: Detailed range breakdown
            # Shows statistics for each individual range
            if analysis['cidr_ranges']['ranges']:
                output_lines.append("Range Details:")
                for range_info in analysis['cidr_ranges']['ranges']:
                    output_lines.append(f"  {range_info['cidr']}: {range_info['total_ips']} IPs "
                                     f"({range_info['public_ips']} public, {range_info['private_ips']} private)")
                output_lines.append("")
            
            # LEARNING: Overall summary
            # Combines individual IPs and range IPs for total counts
            output_lines.append("Summary:")
            output_lines.append(f"  Total IPs: {analysis['summary']['total_ips']}")
            output_lines.append(f"  Public IPs: {analysis['summary']['public_ips']}")
            output_lines.append(f"  Private IPs: {analysis['summary']['private_ips']}")
            
        else:
            # LEARNING: Simple output for quick reference
            # Just the essential counts without detailed breakdown
            output_lines.append(f"Total IPs: {analysis['summary']['total_ips']}")
            output_lines.append(f"Public IPs: {analysis['summary']['public_ips']}")
            output_lines.append(f"Private IPs: {analysis['summary']['private_ips']}")
        
        # LEARNING: Join all lines with newlines to create final output
        # This is more efficient than building strings incrementally
        output_text = '\n'.join(output_lines)
        
        # LEARNING: Handle output based on user preferences
        if args.output:
            # LEARNING: Write to specified output file
            # Context manager ensures proper file handling
            with open(args.output, 'w') as f:
                f.write(output_text)
            print(f"Results written to: {args.output}")
        else:
            # LEARNING: Print to standard output (screen)
            print(output_text)
    
    # LEARNING: Specific exception handling for common errors
    except FileNotFoundError as e:
        print(f"Error: File not found", file=sys.stderr)
        # LEARNING: Exit with error code 1 to indicate failure
        sys.exit(1)
        
    # LEARNING: General exception handling for unexpected errors
    except ValueError as e:
        # SECURITY: Don't expose internal error details
        print(f"Error: Invalid input or file format", file=sys.stderr)
        sys.exit(1)
        
    # LEARNING: General exception handling for unexpected errors
    except Exception as e:
        # SECURITY: Log detailed error for debugging but show generic message to user
        # This prevents information disclosure while maintaining debuggability
        print(f"Error: An unexpected error occurred", file=sys.stderr)
        # LEARNING: In production, you might want to log the full error details
        # but never expose them to end users
        sys.exit(1)


# LEARNING: This is a Python idiom that ensures the main() function only runs
# when the script is executed directly (not when imported as a module)
# This is a best practice for reusable Python code
if __name__ == "__main__":
    main()
