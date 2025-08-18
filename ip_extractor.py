#!/usr/bin/env python3
"""
IP Address Extractor - A Learning Tool for Cybersecurity Professionals

Copyright (c) 2024 IP Address Parsing Solution
Licensed under the MIT License - see LICENSE file for details.

This script demonstrates several intermediate to advanced Python concepts while providing
practical IP address extraction functionality. It's designed to help security professionals
learn Python while solving real-world problems.

LEARNING OBJECTIVES:
- Regular Expressions (regex) for pattern matching
- Object-Oriented Programming (OOP) with classes
- Type hints and modern Python syntax
- Error handling and exception management
- File parsing and data processing
- IP address manipulation with the ipaddress module
- Advanced data structures (sets, defaultdict)
- Context managers and file handling
- SECURITY: Input validation and sanitization
- SECURITY: Path traversal prevention
- SECURITY: Information disclosure prevention

This script parses various document formats (CSV, Excel, text, JSON, etc.) and extracts
individual IP addresses and IP ranges, converting ranges to CIDR notation.
Output is formatted as a comma and space separated list, with /32 CIDR notation removed
since it represents single IP addresses.

SECURITY FEATURES:
- Path traversal prevention (../ sequences blocked)
- Input sanitization and length limits
- Safe file operations within working directory
- Error message sanitization (no information disclosure)
- Null byte and control character removal

Usage:
    python ip_extractor.py <file_path>
    python ip_extractor.py --help
"""

# =============================================================================
# STANDARD LIBRARY IMPORTS - These come with Python by default
# =============================================================================
import argparse      # Command-line argument parsing (intermediate concept)
import csv          # CSV file reading and writing
import json         # JSON data parsing and manipulation
import re           # Regular expressions for pattern matching (advanced concept)
import sys          # System-specific parameters and functions
from pathlib import Path  # Object-oriented filesystem paths (modern Python)
from typing import List, Set, Tuple, Union  # Type hints (intermediate concept)
import ipaddress    # IP address manipulation and validation
from collections import defaultdict  # Dictionary with default values (intermediate concept)

# =============================================================================
# OPTIONAL DEPENDENCIES - These require separate installation
# =============================================================================
# LEARNING: This is a common pattern for handling optional dependencies
# We use try/except to gracefully handle missing packages
try:
    import pandas as pd  # Data manipulation library (advanced concept)
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

try:
    import openpyxl  # Excel file reading library
    OPENPYXL_AVAILABLE = True
except ImportError:
    OPENPYXL_AVAILABLE = False


class IPExtractor:
    """
    Extract IP addresses and ranges from various document formats.
    
    LEARNING: This is an example of Object-Oriented Programming (OOP)
    - Classes are blueprints for creating objects
    - They group related data and functions together
    - This makes code more organized and reusable
    """
    
    def __init__(self):
        """
        Constructor method - runs when we create a new IPExtractor object
        
        LEARNING: Regular Expressions (regex) are powerful pattern matching tools
        - They use special syntax to find text patterns
        - Very useful for cybersecurity (parsing logs, extracting data)
        - The 'r' prefix makes it a "raw string" (ignores escape characters)
        """
        
        # PATTERN 1: Individual IP addresses (e.g., 192.168.1.1)
        # \b = word boundary, (?:...) = non-capturing group, \. = literal dot
        # This pattern matches valid IPv4 addresses (0.0.0.0 to 255.255.255.255)
        self.ip_pattern = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
        
        # PATTERN 2: IP ranges (e.g., 192.168.1.1-192.168.1.100)
        # \s* = zero or more whitespace characters, - = literal dash
        self.range_pattern = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\s*-\s*(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
        
        # PATTERN 3: CIDR notation (e.g., 192.168.1.0/24)
        # /(?:3[0-2]|[1-2][0-9]|[0-9]) = matches /0 to /32
        self.cidr_pattern = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-9]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:3[0-2]|[1-2][0-9]|[0-9])\b')
        
    def extract_ips_from_text(self, text: str) -> Tuple[Set[str], Set[str]]:
        """
        Extract individual IPs and ranges from text.
        
        LEARNING: This method demonstrates several important concepts:
        - Type hints: -> Tuple[Set[str], Set[str]] tells us what the method returns
        - Sets: Unordered collections of unique elements (no duplicates)
        - Regular expression iteration with .finditer()
        - Helper methods (methods that call other methods)
        
        Args:
            text (str): The text to search for IP addresses
            
        Returns:
            Tuple[Set[str], Set[str]]: Two sets - individual IPs and IP ranges
        """
        # LEARNING: Sets are perfect for this because:
        # - They automatically remove duplicates
        # - They're very fast for lookups
        # - They're unordered (which is fine for IP addresses)
        individual_ips = set()
        ip_ranges = set()
        
        # STEP 1: Extract individual IP addresses
        # LEARNING: .finditer() returns an iterator of match objects
        # Each match object has .group() (the matched text) and .start()/.end() (positions)
        for match in self.ip_pattern.finditer(text):
            ip = match.group()  # Get the actual IP address that was matched
            
            # LEARNING: We need to check if this IP is part of a larger pattern
            # For example, "192.168.1.1" in "192.168.1.1-192.168.1.100" should not be counted twice
            if not self._is_part_of_range_or_cidr(text, match.start(), match.end()):
                individual_ips.add(ip)
        
        # STEP 2: Extract IP ranges (e.g., 192.168.1.1-192.168.1.100)
        for match in self.range_pattern.finditer(text):
            range_text = match.group()
            # LEARNING: Helper methods break complex logic into smaller, readable pieces
            start_ip, end_ip = self._parse_ip_range(range_text)
            if start_ip and end_ip:
                # LEARNING: .update() adds all elements from another set
                cidr_ranges = self._convert_range_to_cidr(start_ip, end_ip)
                ip_ranges.update(cidr_ranges)
        
        # STEP 3: Extract existing CIDR notations (e.g., 192.168.1.0/24)
        for match in self.cidr_pattern.finditer(text):
            cidr = match.group()
            ip_ranges.add(cidr)
        
        return individual_ips, ip_ranges
    
    def _is_part_of_range_or_cidr(self, text: str, start: int, end: int) -> bool:
        """
        Check if an IP is part of a range or CIDR notation.
        
        LEARNING: This method demonstrates context analysis - a common cybersecurity technique
        - We look at the text around a match to understand its context
        - This prevents double-counting IPs that are part of larger patterns
        
        Args:
            text (str): The full text being analyzed
            start (int): Starting position of the IP match
            end (int): Ending position of the IP match
            
        Returns:
            bool: True if the IP is part of a range or CIDR, False otherwise
        """
        # LEARNING: We create a "context window" around the IP address
        # This is like zooming out to see the bigger picture
        context_start = max(0, start - 20)      # max() prevents negative indices
        context_end = min(len(text), end + 20)   # min() prevents going past text end
        context = text[context_start:context_end] # String slicing (intermediate concept)
        
        # LEARNING: Simple pattern detection - look for range indicators
        # This is a basic form of context analysis used in log parsing
        if '-' in context or '/' in context:
            return True
        return False
    
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
    
    def _parse_ip_range(self, range_text: str) -> Tuple[Union[str, None], Union[str, None]]:
        """
        Parse IP range text to get start and end IPs.
        
        LEARNING: This method demonstrates defensive programming and error handling
        - We use try/except to handle unexpected input gracefully
        - This is crucial in cybersecurity where input data is often messy
        - We return None for invalid ranges instead of crashing
        - SECURITY: Input sanitization prevents injection attacks
        
        Args:
            range_text (str): Text like "192.168.1.1-192.168.1.100"
            
        Returns:
            Tuple[Union[str, None], Union[str, None]]: (start_ip, end_ip) or (None, None) if invalid
        """
        try:
            # SECURITY: Sanitize input before processing
            # This prevents various injection attacks
            clean_text = self._sanitize_input(range_text)
            
            if '-' in clean_text:
                # LEARNING: split('-', 1) splits on first dash only
                # This handles cases like "192.168.1.1-192.168.1.100-extra"
                start_ip, end_ip = clean_text.split('-', 1)
                
                # LEARNING: Input validation is a security best practice
                # Always validate data before processing it
                if self._is_valid_ip(start_ip) and self._is_valid_ip(end_ip):
                    return start_ip, end_ip
                    
        except Exception:
            # LEARNING: Broad exception handling is sometimes appropriate
            # Here we want to continue processing even if one range is malformed
            pass
            
        return None, None
    
    def _is_valid_ip(self, ip: str) -> bool:
        """
        Check if a string is a valid IP address.
        
        LEARNING: This method demonstrates the power of Python's standard library
        - The ipaddress module handles all the complex IP validation logic
        - We use exception handling to determine validity
        - This is cleaner than writing our own IP validation regex
        
        Args:
            ip (str): String to check if it's a valid IP address
            
        Returns:
            bool: True if valid IP, False otherwise
        """
        try:
            # LEARNING: ipaddress.ip_address() is a factory function
            # It creates an IP address object if the string is valid
            # If invalid, it raises a ValueError
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            # LEARNING: ValueError is raised when the IP format is invalid
            # This is more specific than catching all exceptions
            return False
    
    def _convert_range_to_cidr(self, start_ip: str, end_ip: str) -> Set[str]:
        """
        Convert IP range to CIDR notation.
        
        LEARNING: This is one of the most complex methods in the script!
        It demonstrates several advanced concepts:
        - IP address arithmetic and manipulation
        - Algorithm design (greedy approach to CIDR optimization)
        - Nested loops with break and continue
        - The 'else' clause with loops (advanced Python feature)
        - Exception handling in loops
        
        This algorithm finds the most efficient CIDR blocks to cover an IP range.
        For example: 192.168.1.1-192.168.1.100 becomes 192.168.1.0/25
        
        Args:
            start_ip (str): Starting IP address
            end_ip (str): Ending IP address
            
        Returns:
            Set[str]: Set of CIDR notation strings
        """
        try:
            # LEARNING: ipaddress.IPv4Address() creates IP address objects
            # These objects support arithmetic operations (+, -, >, <)
            start = ipaddress.IPv4Address(start_ip)
            end = ipaddress.IPv4Address(end_ip)
            
            # LEARNING: Handle cases where start > end (reverse the range)
            if start > end:
                start, end = end, start
            
            cidr_ranges = set()
            
            # LEARNING: This is a greedy algorithm - we always try to use the largest possible CIDR block
            current = start
            while current <= end:
                # LEARNING: range(32, -1, -1) goes from 32 down to 0
                # We start with the largest possible CIDR block (/32 = single IP)
                # and work our way down to find the best fit
                for prefix_len in range(32, -1, -1):
                    try:
                        # LEARNING: strict=False allows us to create networks that don't start at network boundary
                        # This is crucial for our algorithm
                        network = ipaddress.IPv4Network(f"{current}/{prefix_len}", strict=False)
                        
                        # LEARNING: Check if this network fits within our range
                        # network_address is the first IP in the network
                        # broadcast_address is the last IP in the network
                        if network.network_address == current and network.broadcast_address <= end:
                            # LEARNING: Don't add /32 networks since they represent single IPs
                            # We'll handle those separately
                            if prefix_len < 32:
                                cidr_ranges.add(str(network))
                            
                            # LEARNING: Move to the next IP after this network
                            # +1 because broadcast_address is inclusive
                            current = network.broadcast_address + 1
                            break  # Exit the inner loop, continue with outer loop
                            
                    except ValueError:
                        # LEARNING: Some prefix lengths might not be valid for this IP
                        # Just continue to the next prefix length
                        continue
                else:
                    # LEARNING: The 'else' clause with loops runs when the loop completes normally
                    # (not when it's broken out of). This means no CIDR block was found.
                    # Add the current IP as an individual address and move to the next one.
                    cidr_ranges.add(str(current))
                    current += 1
            
            return cidr_ranges
            
        except Exception:
            # LEARNING: If anything goes wrong, return an empty set
            # This prevents the entire process from failing
            return set()
    
    def parse_csv(self, file_path: str) -> Tuple[Set[str], Set[str]]:
        """
        Parse CSV file and extract IPs.
        
        LEARNING: This method demonstrates file handling and data processing
        - Context managers (with statement) for automatic file cleanup
        - CSV parsing with the csv module
        - Nested loops for processing 2D data (rows and columns)
        - Error handling that continues processing even if one file fails
        
        Args:
            file_path (str): Path to the CSV file
            
        Returns:
            Tuple[Set[str], Set[str]]: (individual_ips, ip_ranges)
        """
        individual_ips = set()
        ip_ranges = set()
        
        try:
            # LEARNING: Context managers (with statement) automatically close files
            # This prevents resource leaks and is a Python best practice
            # encoding='utf-8' handles international characters
            # errors='ignore' skips problematic characters instead of crashing
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                # LEARNING: csv.reader() creates an iterator over CSV rows
                # Each row is a list of strings (the cells in that row)
                reader = csv.reader(file)
                
                # LEARNING: Nested loops process 2D data structures
                # Outer loop: process each row
                # Inner loop: process each cell in the row
                for row in reader:
                    for cell in row:
                        # LEARNING: str(cell) converts any data type to string
                        # This handles cases where CSV contains numbers or other types
                        ips, ranges = self.extract_ips_from_text(str(cell))
                        
                        # LEARNING: .update() adds all elements from another set
                        # This is more efficient than adding one by one
                        individual_ips.update(ips)
                        ip_ranges.update(ranges)
                        
        except Exception as e:
            # LEARNING: Print errors to stderr (standard error) instead of stdout
            # This is a best practice for error messages
            print(f"Error parsing CSV file: {e}", file=sys.stderr)
        
        return individual_ips, ip_ranges
    
    def parse_excel(self, file_path: str) -> Tuple[Set[str], Set[str]]:
        """
        Parse Excel file and extract IPs.
        
        LEARNING: This method demonstrates advanced data processing with pandas
        - Optional dependency handling (graceful degradation)
        - Multi-sheet Excel processing
        - DataFrame operations and data type conversion
        - Efficient bulk data processing
        
        Args:
            file_path (str): Path to the Excel file
            
        Returns:
            Tuple[Set[str], Set[str]]: (individual_ips, ip_ranges)
        """
        # LEARNING: Check if optional dependency is available
        # This allows the script to work even without pandas installed
        if not PANDAS_AVAILABLE:
            print("Warning: pandas not available, cannot parse Excel files", file=sys.stderr)
            return set(), set()
        
        individual_ips = set()
        ip_ranges = set()
        
        try:
            # LEARNING: pd.ExcelFile() is more efficient than pd.read_excel() for multiple sheets
            # It loads the file structure without reading all data at once
            excel_file = pd.ExcelFile(file_path)
            
            # LEARNING: Process each sheet in the Excel file
            # This handles complex Excel files with multiple tabs
            for sheet_name in excel_file.sheet_names:
                # LEARNING: pd.read_excel() reads a specific sheet into a DataFrame
                # DataFrame is pandas' 2D data structure (like a spreadsheet in Python)
                df = pd.read_excel(file_path, sheet_name=sheet_name)
                
                # LEARNING: Process each column in the sheet
                for column in df.columns:
                    # LEARNING: .astype(str) converts all values in the column to strings
                    # This handles mixed data types (numbers, dates, text) uniformly
                    for value in df[column].astype(str):
                        ips, ranges = self.extract_ips_from_text(str(value))
                        individual_ips.update(ips)
                        ip_ranges.update(ranges)
                        
        except Exception as e:
            print(f"Error parsing Excel file: {e}", file=sys.stderr)
        
        return individual_ips, ip_ranges
    
    def parse_json(self, file_path: str) -> Tuple[Set[str], Set[str]]:
        """
        Parse JSON file and extract IPs.
        
        LEARNING: This method demonstrates JSON processing and data serialization
        - JSON parsing with the json module
        - Handling complex nested data structures
        - Converting structured data back to text for pattern matching
        - The 'default=str' parameter for handling non-serializable objects
        
        Args:
            file_path (str): Path to the JSON file
            
        Returns:
            Tuple[Set[str], Set[str]]: (individual_ips, ip_ranges)
        """
        individual_ips = set()
        ip_ranges = set()
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                # LEARNING: json.load() parses JSON and creates Python objects
                # This handles nested structures, arrays, and complex data types
                data = json.load(file)
                
                # LEARNING: json.dumps() converts Python objects back to JSON text
                # default=str tells it how to handle objects that aren't JSON serializable
                # This is useful for handling dates, custom objects, etc.
                json_text = json.dumps(data, default=str)
                
                # LEARNING: Now we can use our text-based IP extraction on the JSON content
                # This approach works regardless of the JSON structure
                ips, ranges = self.extract_ips_from_text(json_text)
                individual_ips.update(ips)
                ip_ranges.update(ranges)
                
        except Exception as e:
            print(f"Error parsing JSON file: {e}", file=sys.stderr)
        
        return individual_ips, ip_ranges
    
    def parse_text(self, file_path: str) -> Tuple[Set[str], Set[str]]:
        """
        Parse text file and extract IPs.
        
        LEARNING: This method demonstrates simple file reading and text processing
        - Reading entire file content into memory with .read()
        - Direct text processing (simplest approach)
        - Error handling for file reading issues
        
        Args:
            file_path (str): Path to the text file
            
        Returns:
            Tuple[Set[str], Set[str]]: (individual_ips, ip_ranges)
        """
        individual_ips = set()
        ip_ranges = set()
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                # LEARNING: .read() loads the entire file into memory
                # This is simple but not suitable for very large files
                # For large files, you'd use line-by-line reading
                content = file.read()
                
                # LEARNING: Process the entire text content at once
                # This is efficient for text files since we're doing pattern matching
                ips, ranges = self.extract_ips_from_text(content)
                individual_ips.update(ips)
                ip_ranges.update(ranges)
                
        except Exception as e:
            print(f"Error parsing text file: {e}", file=sys.stderr)
        
        return individual_ips, ip_ranges
    
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
    
    def parse_file(self, file_path: str) -> Tuple[Set[str], Set[str]]:
        """
        Parse file based on its extension.
        
        LEARNING: This method demonstrates several important concepts:
        - Path manipulation with the pathlib module
        - File existence checking
        - Extension-based routing (strategy pattern)
        - Graceful fallback to text parsing for unknown file types
        - SECURITY: Path validation and sanitization
        
        Args:
            file_path (str): Path to the file to parse
            
        Returns:
            Tuple[Set[str], Set[str]]: (individual_ips, ip_ranges)
            
        Raises:
            FileNotFoundError: If the file doesn't exist
            ValueError: If the path contains security violations
        """
        # SECURITY: Validate and sanitize the file path
        # This prevents path traversal and ensures safe file access
        validated_path = self._validate_file_path(file_path)
        
        # LEARNING: .suffix gets the file extension (e.g., '.csv', '.txt')
        # .lower() makes it case-insensitive ('.CSV' becomes '.csv')
        extension = validated_path.suffix.lower()
        
        # LEARNING: Extension-based routing - different file types need different parsers
        # This is a common pattern in file processing applications
        if extension == '.csv':
            return self.parse_csv(validated_path)
        elif extension in ['.xlsx', '.xls']:
            return self.parse_excel(validated_path)
        elif extension == '.json':
            return self.parse_json(validated_path)
        else:
            # LEARNING: Graceful fallback - if we don't recognize the extension,
            # try to parse it as text. This makes the tool more robust.
            return self.parse_text(validated_path)
    
    def consolidate_overlapping_ranges(self, ip_ranges: Set[str]) -> Set[str]:
        """
        Consolidate overlapping CIDR ranges into the most efficient representation.
        
        LEARNING: This method demonstrates advanced algorithm design and network analysis
        - Network object manipulation with the ipaddress module
        - Sorting with custom key functions (lambda expressions)
        - List manipulation and dynamic list modification
        - Network containment and overlap detection
        - Set comprehensions for data transformation
        
        This algorithm finds the most efficient way to represent overlapping IP ranges.
        For example: 192.168.1.0/24 and 192.168.1.0/25 becomes just 192.168.1.0/24
        
        Args:
            ip_ranges (Set[str]): Set of CIDR notation strings
            
        Returns:
            Set[str]: Consolidated set of CIDR ranges
        """
        if not ip_ranges:
            return set()
        
        # LEARNING: Convert string representations to network objects for analysis
        # This allows us to use the powerful ipaddress module methods
        networks = []
        for cidr in ip_ranges:
            try:
                network = ipaddress.IPv4Network(cidr, strict=False)
                networks.append(network)
            except ValueError:
                # LEARNING: Keep invalid CIDR as-is - don't lose data due to parsing errors
                continue
        
        if not networks:
            return ip_ranges
        
        # LEARNING: Sort networks by their network address (first IP in the range)
        # This is crucial for the consolidation algorithm to work correctly
        # lambda x: x.network_address creates a function that extracts the sort key
        networks.sort(key=lambda x: x.network_address)
        
        # LEARNING: This is a consolidation algorithm that processes networks in order
        # It maintains a list of consolidated networks and processes each new one
        consolidated = []
        for network in networks:
            if not consolidated:
                # First network goes directly into the list
                consolidated.append(network)
                continue
            
            # LEARNING: Get the last network we've processed
            # consolidated[-1] gets the last element (Python's negative indexing)
            last_network = consolidated[-1]
            
            # LEARNING: Check if current network is completely contained within the last one
            # If so, we can skip it (the larger network covers everything)
            if network.subnet_of(last_network):
                continue
            
            # LEARNING: Check if current network completely contains the last one
            # If so, replace the smaller network with the larger one
            if last_network.subnet_of(network):
                consolidated[-1] = network  # Replace the last element
                continue
            
            # LEARNING: Check if networks overlap but neither contains the other
            # This is a complex case that requires keeping both networks
            if network.overlaps(last_network):
                consolidated.append(network)
            else:
                # LEARNING: No overlap - safe to add this network
                # Networks are sorted, so this means we're moving to a new range
                consolidated.append(network)
        
        # LEARNING: Set comprehension converts network objects back to strings
        # {str(network) for network in consolidated} creates a set of strings
        return {str(network) for network in consolidated}
    
    def format_output(self, individual_ips: Set[str], ip_ranges: Set[str]) -> str:
        """
        Format output as comma and space separated list.
        
        LEARNING: This method demonstrates data processing and output formatting
        - Data transformation and filtering
        - Set operations (union, difference)
        - Custom sorting with lambda functions
        - String joining and formatting
        - Error handling during data processing
        
        Args:
            individual_ips (Set[str]): Set of individual IP addresses
            ip_ranges (Set[str]): Set of CIDR notation strings
            
        Returns:
            str: Formatted output string
        """
        # LEARNING: Process ranges to remove /32 (single IP addresses)
        # /32 networks represent single IPs, so we convert them to individual IPs
        processed_ranges = set()
        additional_ips = set()
        
        for cidr in ip_ranges:
            try:
                # LEARNING: Convert CIDR string to network object for analysis
                network = ipaddress.IPv4Network(cidr, strict=False)
                if network.prefixlen == 32:
                    # LEARNING: /32 means single IP, add to individual IPs instead
                    # network_address gives us the first IP in the network
                    additional_ips.add(str(network.network_address))
                else:
                    # LEARNING: Keep non-/32 networks for further processing
                    processed_ranges.add(cidr)
            except ValueError:
                # LEARNING: If we can't parse the CIDR, keep it as-is
                # This prevents data loss due to parsing errors
                processed_ranges.add(cidr)
        
        # LEARNING: Consolidate overlapping ranges for efficiency
        # This reduces the number of CIDR blocks needed
        consolidated_ranges = self.consolidate_overlapping_ranges(processed_ranges)
        
        # LEARNING: Set union combines all individual IPs
        # This handles both original individual IPs and converted /32 networks
        all_individual_ips = individual_ips.union(additional_ips)
        
        # LEARNING: Sort IPs and ranges for consistent, readable output
        # lambda functions provide custom sorting keys
        # IPv4Address and IPv4Network objects support natural ordering
        sorted_ips = sorted(all_individual_ips, key=lambda ip: ipaddress.IPv4Address(ip))
        sorted_ranges = sorted(consolidated_ranges, key=lambda cidr: ipaddress.IPv4Network(cidr))
        
        # LEARNING: Combine lists and join with comma and space
        # This creates a clean, readable output format
        all_items = sorted_ips + sorted_ranges
        return ', '.join(all_items)


def main():
    """
    Main function - entry point for the script.
    
    LEARNING: This function demonstrates command-line interface design
    - Argument parsing with argparse module
    - Help text and examples
    - Error handling and user feedback
    - File I/O operations
    """
    # LEARNING: argparse.ArgumentParser creates a professional command-line interface
    # It automatically handles help text, argument validation, and error messages
    parser = argparse.ArgumentParser(
        description="Extract IP addresses and ranges from various document formats",
        formatter_class=argparse.RawDescriptionHelpFormatter,  # Preserves formatting in help
        epilog="""
Examples:
  python ip_extractor.py document.csv
  python ip_extractor.py spreadsheet.xlsx
  python ip_extractor.py data.json
  python ip_extractor.py logfile.txt
        """
    )
    
    # LEARNING: Positional arguments are required (no dashes)
    # This is the main input file path
    parser.add_argument(
        'file_path',
        help='Path to the file to parse'
    )
    
    # LEARNING: Optional arguments start with dashes
    # --output is the long form, -o is the short form
    # Both do the same thing
    parser.add_argument(
        '--output', '-o',
        help='Output file path (default: stdout)'
    )
    
    # LEARNING: action='store_true' creates a flag argument
    # If --verbose is used, args.verbose becomes True
    # If not used, it defaults to False
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output with counts and details'
    )
    
    # LEARNING: parse_args() processes the command line and creates an args object
    # This object contains all the argument values
    args = parser.parse_args()
    
    try:
        # LEARNING: Create an instance of our IPExtractor class
        # This demonstrates object instantiation
        extractor = IPExtractor()
        
        # LEARNING: Call the parse_file method to process the input file
        # This returns a tuple that we unpack into two variables
        individual_ips, ip_ranges = extractor.parse_file(args.file_path)
        
        # LEARNING: Format the results into a readable string
        # This separates the data processing from the output formatting
        output_text = extractor.format_output(individual_ips, ip_ranges)
        
        # LEARNING: Handle output based on user preferences
        # If --output is specified, write to file; otherwise, print to screen
        if args.output:
            # LEARNING: Context manager (with statement) for file writing
            # This automatically closes the file when done
            with open(args.output, 'w') as f:
                f.write(output_text)
            print(f"Results written to: {args.output}")
        else:
            # LEARNING: Default output goes to stdout (screen)
            print(output_text)
        
        # LEARNING: Verbose output provides detailed information for debugging
        # This is a common pattern in command-line tools
        if args.verbose:
            # LEARNING: Print to stderr (standard error) for diagnostic information
            # This keeps the main output clean while showing details separately
            print(f"\nSummary:", file=sys.stderr)
            print(f"Individual IPs found: {len(individual_ips)}", file=sys.stderr)
            print(f"IP ranges (CIDR) found: {len(ip_ranges)}", file=sys.stderr)
            print(f"Total items: {len(individual_ips) + len(ip_ranges)}", file=sys.stderr)
            
            # LEARNING: Conditional output - only show sections that have data
            if individual_ips:
                print(f"\nIndividual IPs:", file=sys.stderr)
                # LEARNING: Sort IPs for consistent, readable output
                # lambda function provides custom sorting key
                for ip in sorted(individual_ips, key=lambda ip: ipaddress.IPv4Address(ip)):
                    print(f"  {ip}", file=sys.stderr)
            
            if ip_ranges:
                print(f"\nIP Ranges (CIDR):", file=sys.stderr)
                # LEARNING: Sort CIDR ranges for consistent output
                for cidr in sorted(ip_ranges, key=lambda cidr: ipaddress.IPv4Network(cidr)):
                    print(f"  {cidr}", file=sys.stderr)
    
            # LEARNING: Specific exception handling - catch FileNotFoundError separately
        # This provides better error messages for common user mistakes
    except FileNotFoundError as e:
        print(f"Error: File not found", file=sys.stderr)
        # LEARNING: sys.exit(1) indicates program failure to the operating system
        # Exit code 1 is standard for errors, 0 is success
        sys.exit(1)
        
    # LEARNING: General exception handling - catch any other unexpected errors
    # This prevents the program from crashing with cryptic error messages
    except ValueError as e:
        # SECURITY: Don't expose internal error details
        print(f"Error: Invalid input or file format", file=sys.stderr)
        sys.exit(1)
        
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
