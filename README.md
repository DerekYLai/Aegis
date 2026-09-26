# Aegis

A Python-based system diagnostic and defensive security scanner.

Aegis analyzes a Windows system for system information, running processes, security configurations, network exposure, and known file signatures.

## Features

- System and hardware information
- CPU and memory monitoring
- Running process analysis
- Windows Firewall checks
- Windows Defender checks
- Listening-port analysis
- SHA-256 file signature scanning
- Security findings with severity levels

## Technologies

- Python
- psutil
- PowerShell
- JSON
- SHA-256
- Git / GitHub

## How It Works

Aegis provides a command-line menu that allows the user to run different security and diagnostic scans.

The scanner collects information from the local system and creates security findings when potential issues are detected.

Signature scanning compares SHA-256 file hashes against a local signature database.

## Project Structure

```text
Aegis/
├── main.py
└── signatures/
    └── signatures.json