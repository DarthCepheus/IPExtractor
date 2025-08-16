# Installation Guide

## Prerequisites

This script requires **Python 3.6 or higher**. Python is not included with Windows by default.

## Installing Python on Windows

### Option 1: Microsoft Store (Recommended for Beginners)

1. **Open Microsoft Store**
   - Press `Windows + S` and type "Microsoft Store"
   - Click on the Microsoft Store app

2. **Search for Python**
   - In the search bar, type "Python 3.11" or "Python 3.12"
   - Look for the official Python app by Python Software Foundation

3. **Install Python**
   - Click "Get" or "Install"
   - Wait for the installation to complete

4. **Verify Installation**
   - Open Command Prompt or PowerShell
   - Type: `python --version`
   - You should see the Python version number

### Option 2: Python.org (Advanced Users)

1. **Download Python**
   - Go to [https://www.python.org/downloads/](https://www.python.org/downloads/)
   - Click "Download Python 3.11.x" (latest stable version)

2. **Run Installer**
   - **IMPORTANT**: Check "Add Python to PATH" during installation
   - Choose "Install Now" for standard installation
   - Wait for installation to complete

3. **Verify Installation**
   - Open Command Prompt or PowerShell
   - Type: `python --version`
   - You should see the Python version number

## Installing Optional Dependencies

For enhanced functionality (Excel file support), install additional packages:

```bash
pip install -r requirements.txt
```

Or install individually:
```bash
pip install pandas openpyxl
```

## Running the Script

### Method 1: Command Line
```bash
python ip_extractor.py <file_path>
```

### Method 2: Windows Batch File
```bash
run_ip_extractor.bat <file_path>
```

### Method 3: PowerShell Script
```powershell
.\run_ip_extractor.ps1 <file_path>
```

## Troubleshooting

### "Python is not recognized as an internal or external command"

**Solution**: Python is not in your PATH
1. Reinstall Python and make sure to check "Add Python to PATH"
2. Or manually add Python to PATH:
   - Find your Python installation (usually `C:\Users\YourName\AppData\Local\Programs\Python\Python3x\`)
   - Add this path to your system PATH environment variable

### "pip is not recognized"

**Solution**: pip is not in your PATH
1. Reinstall Python and make sure to check "Add Python to PATH"
2. Or use: `python -m pip install <package>`

### Permission Errors

**Solution**: Run Command Prompt or PowerShell as Administrator

### Excel Files Not Working

**Solution**: Install required packages
```bash
pip install pandas openpyxl
```

## Testing the Installation

1. **Create a test file**:
   ```bash
   echo "IP: 192.168.1.1" > test.txt
   ```

2. **Run the script**:
   ```bash
   python ip_extractor.py test.txt
   ```

3. **Expected output**:
   ```
   192.168.1.1
   ```

## Getting Help

If you encounter issues:

1. **Check Python version**: `python --version`
2. **Check pip version**: `pip --version`
3. **Verify PATH**: `echo $env:PATH` (PowerShell) or `echo %PATH%` (Command Prompt)
4. **Reinstall Python** if necessary

## Alternative: Using Python Launcher

If you have multiple Python versions, you can use the Python Launcher:

```bash
py -3 ip_extractor.py <file_path>
```

This will automatically use the latest Python 3.x version installed on your system.
