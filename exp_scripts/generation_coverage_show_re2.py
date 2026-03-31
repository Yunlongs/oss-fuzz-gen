#!/usr/bin/env python3
"""
Script to filter out lines containing 'absl' from coverage report and recalculate coverage statistics.
"""

import re
import sys
import argparse



def parse_coverage_line(line):
    """Parse a coverage data line and extract numeric values."""
    # Split by whitespace and extract numeric values
    parts = line.split()
    if len(parts) < 13:
        return None
    
    try:
        # Extract coverage data based on the format:
        # Filename Regions Missed_Regions Cover% Functions Missed_Functions Executed% Lines Missed_Lines Cover% Branches Missed_Branches Cover%
        data = {
            'filename': parts[0],
            'regions': int(parts[1]),
            'missed_regions': int(parts[2]),
            'regions_pct': float(parts[3].rstrip('%')),
            'functions': int(parts[4]),
            'missed_functions': int(parts[5]),
            'functions_pct': float(parts[6].rstrip('%')),
            'lines': int(parts[7]),
            'missed_lines': int(parts[8]),
            'lines_pct': float(parts[9].rstrip('%')),
            'branches': int(parts[10]),
            'missed_branches': int(parts[11]),
            'branches_pct': float(parts[12].rstrip('%'))
        }
        return data
    except (ValueError, IndexError):
        return None


def calculate_coverage_percentage(total, missed):
    """Calculate coverage percentage."""
    if total == 0:
        return 0.0
    return ((total - missed) / total) * 100.0


def filter_and_calculate_coverage(report_file):
    """Filter out absl lines and calculate coverage statistics."""
    
    # Read all lines
    with open(report_file, 'r') as f:
        lines = f.readlines()
    
    # Filter out lines containing 'absl' (case-insensitive)
    filtered_lines = []
    absl_count = 0
    
    for line in lines:
        if 'absl' in line.lower():
            absl_count += 1
        else:
            filtered_lines.append(line)
    
    print(f"Filtered out {absl_count} lines containing 'absl'\n")
    
    # Parse coverage data
    total_regions = 0
    total_missed_regions = 0
    total_functions = 0
    total_missed_functions = 0
    total_lines = 0
    total_missed_lines = 0
    total_branches = 0
    total_missed_branches = 0
    
    # Skip header and footer lines, process only data lines
    for line in filtered_lines:
        # Skip header, separator, and summary lines
        if line.startswith('Filename') or line.startswith('---') or \
           line.startswith('TOTAL') or line.startswith('Files which contain'):
            continue
        
        # Try to parse the line
        data = parse_coverage_line(line.strip())
        if data:
            total_regions += data['regions']
            total_missed_regions += data['missed_regions']
            total_functions += data['functions']
            total_missed_functions += data['missed_functions']
            total_lines += data['lines']
            total_missed_lines += data['missed_lines']
            total_branches += data['branches']
            total_missed_branches += data['missed_branches']
    
    # Calculate percentages
    regions_pct = calculate_coverage_percentage(total_regions, total_missed_regions)
    functions_pct = calculate_coverage_percentage(total_functions, total_missed_functions)
    lines_pct = calculate_coverage_percentage(total_lines, total_missed_lines)
    branches_pct = calculate_coverage_percentage(total_branches, total_missed_branches)
    
    # Print results
    print("=" * 80)
    print("Coverage Statistics (after filtering absl)")
    print("=" * 80)
    print(f"Regions:    {total_regions:6} total, {total_missed_regions:6} missed, {regions_pct:6.2f}% covered")
    print(f"Functions:  {total_functions:6} total, {total_missed_functions:6} missed, {functions_pct:6.2f}% covered")
    print(f"Lines:      {total_lines:6} total, {total_missed_lines:6} missed, {lines_pct:6.2f}% covered")
    print(f"Branches:   {total_branches:6} total, {total_missed_branches:6} missed, {branches_pct:6.2f}% covered")
    print("=" * 80)
    
    return {
        'regions': (total_regions, total_missed_regions, regions_pct),
        'functions': (total_functions, total_missed_functions, functions_pct),
        'lines': (total_lines, total_missed_lines, lines_pct),
        'branches': (total_branches, total_missed_branches, branches_pct)
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Filter out 'absl' lines from coverage report and recalculate coverage statistics.")
    parser.add_argument('report', type=str, default="", help='Path to the coverage report file')
    args = parser.parse_args()
    try:
        stats = filter_and_calculate_coverage(args.report)
    except FileNotFoundError:
        print(f"Error: Coverage report file not found: {args.report}")
        sys.exit(1)
    except Exception as e:
        print(f"Error processing coverage report: {e}")
        sys.exit(1)