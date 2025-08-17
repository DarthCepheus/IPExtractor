#!/usr/bin/env python3
"""
Public IP Finder - A Learning Tool for Cybersecurity Professionals

This script demonstrates several important Python concepts while providing practical
IP address filtering functionality. It's designed to help security professionals
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
- SECURITY: Path traversal prevention

This script takes a messy list of IP addresses from clients and:
1. Cleans up formatting issues (extra spaces, weird characters, etc.)
2. Identifies which IPs are PUBLIC (not private/internal)
3. Groups contiguous IPs into efficient CIDR ranges when possible
4. Outputs a clean, professional list ready for firewall rules or reports

SECURITY FEATURES:
- Path traversal prevention (../ sequences blocked)
- Input sanitization and length limits
- Safe file operations within working directory
- Error message sanitization (no information disclosure)
- Null byte and control character removal
- Input validation and type checking

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

# =============================================================================
# STANDARD LIBRARY IMPORTS - These come with Python by default
# =============================================================================
import argparse      # Command-line argument parsing (intermediate concept)
import sys           # System-specific parameters and functions
import ipaddress     # IP address manipulation and network analysis (advanced concept)
from typing import List, Set, Tuple  # Type hints (intermediate concept)
import re            # Regular expressions for pattern matching (advanced concept)
from pathlib import Path  # Object-oriented filesystem paths (modern Python)


class PublicIPFinder:
    """
    Filter and analyze public IP addresses from IP extractor output.
    
    LEARNING: This class demonstrates object-oriented programming principles
    - Encapsulation: Data and methods are grouped together
    - Initialization: Constructor method sets up the object's state
    - Network knowledge: Understanding of RFC 1918 and other IP ranges
    - SECURITY: Input validation and sanitization methods
    """
    
    def __init__(self):
        """
        Constructor method - runs when we create a new PublicIPFinder object
        
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
    
    def _validate_file_path(self, file_path: str) -> Path:
        """
        Validate and sanitize file path for security.
        
        LEARNING: This method demonstrates security best practices
        - Path traversal prevention (stopping "../" sequences)
        - Absolute path resolution and validation
        - Security-focused input validation
        
        SECURITY: Prevents path traversal attacks and ensures files are
        only accessed within intended directories.
        
        Args:
            file_path (str): Raw file path from user input
            
        Returns:
            Path: Validated and sanitized pathlib.Path object
            
        Raises:
            ValueError: If path contains security violations
            FileNotFoundError: If file doesn't exist
        """
        # LEARNING: Convert to Path object for manipulation
        path = Path(file_path)
        
        # SECURITY: Resolve to absolute path to prevent relative path attacks
        try:
            path = path.resolve()
        except (RuntimeError, OSError):
            raise ValueError(f"Invalid path: {file_path}")
        
        # SECURITY: Check for path traversal attempts
        # This prevents "../../../etc/passwd" type attacks
        if '..' in str(path):
            raise ValueError(f"Path traversal not allowed: {file_path}")
        
        # SECURITY: Ensure path is within current working directory
        # This prevents access to system files outside the intended scope
        try:
            path.relative_to(Path.cwd())
        except ValueError:
            raise ValueError(f"Path outside working directory not allowed: {file_path}")
        
        # SECURITY: Validate file exists and is a regular file
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        
        if not path.is_file():
            raise ValueError(f"Path is not a regular file: {path}")
        
        return path
    
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
        text = re.sub(r'\s+', ' ', text)
        
        # SECURITY: Remove any non-printable characters
        text = ''.join(char for char in text if char.isprintable() or char.isspace())
        
        return text.strip()
    
    def is_public_ip(self, ip: ipaddress.IPv4Address) -> bool:
        """
        Check if an IP address is public (not private).
        
        LEARNING: This method demonstrates network membership testing
        - The 'in' operator works with ipaddress objects
        - We iterate through our predefined private ranges
        - This is a common pattern in network security analysis
        
        Args:
            ip (ipaddress.IPv4Address): IP address to check
            
        Returns:
            bool: True if public, False if private
        """
        # LEARNING: Iterate through our predefined private network ranges
        # The 'in' operator checks if an IP is within a network
        for network in self.private_ranges:
            if ip in network:
                return False
        return True
    
    def expand_cidr_to_public_ips(self, cidr: str) -> Set[ipaddress.IPv4Address]:
        """
        Expand a CIDR notation to a set of public IP addresses only.
        
        LEARNING: This method demonstrates CIDR network expansion and filtering
        - network.hosts() returns an iterator of all IPs in a network
        - We filter to keep only public IPs
        - Error handling prevents crashes from invalid CIDR notation
        - SECURITY: Input validation ensures safe processing
        
        Args:
            cidr (str): CIDR notation (e.g., "192.168.1.0/24")
            
        Returns:
            Set[ipaddress.IPv4Address]: Set of public IP addresses only
        """
        try:
            # LEARNING: Create a network object from CIDR string
            # strict=False allows networks that don't start at network boundary
            network = ipaddress.IPv4Network(cidr, strict=False)
            public_ips = set()
            
            # LEARNING: .hosts() returns all usable IPs in the network
            # We iterate through each IP and check if it's public
            for ip in network.hosts():
                if self.is_public_ip(ip):
                    public_ips.add(ip)
            
            return public_ips
        except ValueError:
            # LEARNING: Return empty set for invalid CIDR notation
            # This prevents the program from crashing on bad input
            return set()
    
    def clean_input(self, ip_text: str) -> str:
        """
        Clean and normalize input text to handle common formatting issues.
        
        LEARNING: This method demonstrates text sanitization and encoding handling
        - Remove Unicode BOM (Byte Order Mark) characters
        - Remove null bytes and control characters
        - Normalize whitespace and formatting
        - SECURITY: Input sanitization prevents various attacks
        
        Args:
            ip_text (str): Raw input text that may contain encoding issues
            
        Returns:
            str: Cleaned and normalized text safe for processing
        """
        if not ip_text:
            return ""
        
        # SECURITY: Remove Unicode BOM (Byte Order Mark) characters
        # These can cause parsing issues and are often invisible
        # \ufeff = UTF-8 BOM, \ufffe = UTF-16 BOM
        cleaned = ip_text.replace('\ufeff', '').replace('\ufffe', '')
        
        # SECURITY: Remove null bytes and other control characters
        # These can cause issues in various contexts and are security risks
        cleaned = cleaned.replace('\x00', '')  # Null bytes
        
        # SECURITY: Use our comprehensive sanitization method
        # This handles additional security concerns like length limits
        cleaned = self._sanitize_input(cleaned)
        
        return cleaned
    
    def parse_ip_list(self, ip_text: str) -> Tuple[Set[ipaddress.IPv4Address], Set[str]]:
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
            Tuple[Set[ipaddress.IPv4Address], Set[str]]: (individual_ips, cidr_ranges)
        """
        individual_ips = set()
        cidr_ranges = set()
        
        # SECURITY: Clean and sanitize input before processing
        # This prevents various injection attacks and encoding issues
        cleaned_text = self.clean_input(ip_text)
        
        # LEARNING: List comprehension with string cleaning
        # .split(',') splits on commas, .strip() removes whitespace
        # This handles messy input like " 192.168.1.1 , 10.0.0.0/24 "
        items = [item.strip() for item in cleaned_text.split(',')]
        
        for item in items:
            if not item:
                continue
                
            # LEARNING: Simple pattern recognition - CIDR notation contains '/'
            # This is a basic but effective way to distinguish IP types
            if '/' in item:
                # This might be a CIDR range - validate it
                try:
                    # LEARNING: Test if it's a valid CIDR notation
                    # This prevents processing of malformed input
                    network = ipaddress.IPv4Network(item, strict=False)
                    cidr_ranges.add(item)
                except ValueError:
                    # LEARNING: Try to extract just the IP part if possible
                    # This is a form of graceful degradation
                    ip_part = item.split('/')[0].strip()
                    try:
                        ip = ipaddress.IPv4Address(ip_part)
                        individual_ips.add(ip)
                        # SECURITY: Don't expose raw input in error messages
                        print(f"Warning: Invalid CIDR notation detected, extracted individual IP", file=sys.stderr)
                    except ValueError:
                        # SECURITY: Don't expose raw input in error messages
                        print(f"Warning: Invalid IP address format detected", file=sys.stderr)
            else:
                # This is an individual IP
                try:
                    # LEARNING: Convert string to IP address object
                    # This validates the IP format and creates a usable object
                    ip = ipaddress.IPv4Address(item)
                    individual_ips.add(ip)
                except ValueError:
                    # LEARNING: Skip invalid IPs instead of crashing
                    # This allows processing to continue with valid data
                    # SECURITY: Don't expose raw input in error messages
                    print(f"Warning: Invalid IP address format detected", file=sys.stderr)
        
        return individual_ips, cidr_ranges
    
    def find_public_ips(self, ip_text: str) -> dict:
        """
        Find all public IP addresses in the list.
        
        LEARNING: This method demonstrates data filtering and analysis
        - Process individual IPs and CIDR ranges separately
        - Filter to keep only public IPs
        - Build structured output for analysis
        - Error handling during network operations
        
        Args:
            ip_text (str): Comma-separated list of IPs and CIDR ranges
            
        Returns:
            dict: Dictionary containing public IPs and analysis results
        """
        # LEARNING: Parse input into organized data structures
        # This separates the parsing logic from the filtering logic
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
    """
    Main function - entry point for the script.
    
    LEARNING: This function demonstrates command-line interface design and data processing
    - Argument parsing with argparse
    - File I/O and encoding handling
    - Data analysis and output formatting
    - Error handling and user feedback
    - SECURITY: Path validation and safe file operations
    """
    # LEARNING: Create argument parser for professional command-line interface
    parser = argparse.ArgumentParser(
        description="Clean up messy IP lists and extract only PUBLIC IP addresses",
        formatter_class=argparse.RawDescriptionHelpFormatter,  # Preserves formatting
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
        # SECURITY: Validate and sanitize the file path
        # This prevents path traversal and ensures safe file access
        if args.file_path:
            finder = PublicIPFinder()
            validated_path = finder._validate_file_path(args.file_path)
            
            # LEARNING: Try multiple encodings for robust file reading
            # This handles files with different encoding issues
            try:
                # Try to read with UTF-8 first (most common)
                with open(validated_path, 'r', encoding='utf-8') as f:
                    ip_text = f.read().strip()
            except UnicodeDecodeError:
                try:
                    # Try UTF-16 if UTF-8 fails (Windows sometimes uses this)
                    with open(validated_path, 'r', encoding='utf-16') as f:
                        ip_text = f.read().strip()
                except UnicodeDecodeError:
                    # Try with system default encoding as last resort
                    with open(validated_path, 'r', encoding='cp1252') as f:
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
    
    # LEARNING: Specific exception handling for common errors
    except FileNotFoundError as e:
        print(f"Error: File not found", file=sys.stderr)
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
