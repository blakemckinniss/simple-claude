#!/usr/bin/env python3
import sys
import subprocess
import json

def handle(input_data):
    cwd = input_data.get('cwd', '.')
    result = subprocess.run(['git', 'ls-files'], cwd=cwd, capture_output=True, text=True)
    print(result.stdout.strip())
    sys.exit(0)

if __name__ == "__main__":
    raw_input = sys.stdin.read().strip()
    if raw_input:
        handle(json.loads(raw_input))