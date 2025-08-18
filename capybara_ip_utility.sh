#!/bin/bash
# IP Address Parsing Solution - Interactive Utility
# This shell script walks users through the complete IP parsing workflow

echo
echo "           / /__/ /"
echo
echo "        /      _     \\________________"
echo
echo "      /                                                \\"
echo
echo "     | Y                                                \\"
echo
echo "      \\____/ |                                       |"
echo
echo "          ___/   \\        / ______       _      \\"
echo
echo "        / /____/  |      |             \\     |   \\     /"
echo
echo " ___________// __/  ________// __/ _/ / /_____"
echo
echo "                    CAPYBARA"
echo "              IP Address Parsing Utility"
echo
echo "  \"Let me help you clean up those messy IP lists!\""
echo

# Check if Python is available
if command -v python3 &> /dev/null; then
    echo "[OK] Python3 found! Running interactive utility..."
    echo
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    echo "[OK] Python found! Running interactive utility..."
    echo
    PYTHON_CMD="python"
else
    echo
    echo "ERROR: Python not found!"
    echo
    echo "To use this toolkit, you need to install Python:"
    echo
    echo "Option 1: Install using Homebrew (Recommended for macOS)"
    echo "  - Install Homebrew: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
    echo "  - Install Python: brew install python"
    echo
    echo "Option 2: Install from python.org"
    echo "  - Go to https://www.python.org/downloads/"
    echo "  - Download and install Python 3.11+ for macOS"
    echo
    echo "After installation, restart your terminal and try again."
    echo
    read -p "Press Enter to continue..."
    exit 1
fi

echo "Welcome to the IP Address Parsing Solution!"
echo "This utility will walk you through the complete workflow."
echo

# Step 1: Get input file
echo "Step 1: Input File Selection"
echo "============================="
echo

read -p "Enter the path to your IP list file (e.g., client_ips.txt or ./tests/test_data.txt): " input_file
if [ -z "$input_file" ]; then
    input_file="./tests/test_data.txt"
    echo "Using default test file: $input_file"
fi

if [ ! -f "$input_file" ]; then
    echo "ERROR: File not found: $input_file"
    echo "Please check the file path and try again."
    read -p "Press Enter to continue..."
    exit 1
fi

echo "[OK] Input file found: $input_file"
echo

# Step 2: Clean and deduplicate
echo "Step 2: Clean & Deduplicate"
echo "==========================="
echo

# Get the directory and filename of the input file
input_dir=$(dirname "$input_file")
input_name=$(basename "$input_file" | sed 's/\.[^.]*$//')

read -p "What should we name the cleaned output file? (default: ${input_name}_extrctd.txt): " clean_file
if [ -z "$clean_file" ]; then
    clean_file="${input_dir}/${input_name}_extrctd.txt"
fi
if [[ "$clean_file" != *.txt ]]; then
    clean_file="${clean_file}.txt"
fi

echo "[RUNNING] Cleaning and deduplicating IP addresses..."
$PYTHON_CMD ip_extractor.py "$input_file" --output "$clean_file"
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to clean IP addresses. Please check your input file."
    read -p "Press Enter to continue..."
    exit 1
fi
echo "[OK] Cleaning completed successfully!"
echo

# Step 3: Analyze and count
echo "Step 3: Analyze & Count"
echo "======================="
echo

echo "Let's see what we're working with:"
$PYTHON_CMD ip_counter.py "$clean_file" --detailed
echo

# Step 4: Filter by type
echo "Step 4: Filter by Type"
echo "====================="
echo

echo "Now let's separate your IPs by type:"
echo

# Public IPs
read -p "What should we name the public IPs file? (default: ${input_name}_public.txt): " public_file
if [ -z "$public_file" ]; then
    public_file="${input_dir}/${input_name}_public.txt"
fi
if [[ "$public_file" != *.txt ]]; then
    public_file="${public_file}.txt"
fi

echo "[RUNNING] Extracting public IP addresses..."
$PYTHON_CMD public_ip_finder.py "$clean_file" --output "$public_file"
echo

# Private IPs
read -p "What should we name the private IPs file? (default: ${input_name}_private.txt): " private_file
if [ -z "$private_file" ]; then
    private_file="${input_dir}/${input_name}_private.txt"
fi
if [[ "$private_file" != *.txt ]]; then
    private_file="${private_file}.txt"
fi

echo "[RUNNING] Extracting private IP addresses..."
$PYTHON_CMD private_ip_finder.py "$clean_file" --output "$private_file"
echo

# Summary
echo
echo "WORKFLOW COMPLETE!"
echo "=================="
echo
echo "Files created:"
echo "  [FILE] $clean_file - Cleaned and deduplicated IP list"
echo "  [FILE] $public_file - External/Internet-facing IPs"
echo "  [FILE] $private_file - Internal/private network IPs"
echo
echo "You can now use these files for:"
echo "  • Security scanner configuration"
echo "  • Firewall rule creation"
echo "  • Network documentation"
echo "  • Compliance reporting"
echo

echo "CAPYBARA says: \"Your IP lists are now clean and organized!\""
echo

# Offer to run scripts independently
echo "Want to run scripts independently?"
echo "You can always use:"
echo "  $PYTHON_CMD ip_extractor.py --help"
echo "  $PYTHON_CMD ip_counter.py --help"
echo "  $PYTHON_CMD public_ip_finder.py --help"
echo "  $PYTHON_CMD private_ip_finder.py --help"
echo

read -p "Press Enter to continue..."
