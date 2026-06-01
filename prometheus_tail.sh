#!/bin/bash
# Tail prometheus scan activity in real-time
# Usage: ./prometheus_tail.sh [run_id]
# If no run_id given, uses the latest active scan

COMMS_DIR="$HOME/.prometheus/comms"

if [ -n "$1" ]; then
    RUN_ID="$1"
else
    RUN_ID=$(ls -t "$COMMS_DIR" 2>/dev/null | head -1)
fi

if [ -z "$RUN_ID" ]; then
    echo "No active prometheus scans found"
    echo "Active scans: $(ls "$COMMS_DIR" 2>/dev/null)"
    exit 1
fi

STATUS_FILE="$COMMS_DIR/$RUN_ID/status.jsonl"
FINDINGS_FILE="$COMMS_DIR/$RUN_ID/findings.json"

echo "=== prometheus Scan: $RUN_ID ==="
echo "Status: $STATUS_FILE"
echo "Findings: $FINDINGS_FILE"
echo "---"
echo "Tailing... (Ctrl+C to stop)"
echo ""

tail -f "$STATUS_FILE" 2>/dev/null | python3 -c "
import sys, json

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        e = json.loads(line)
        ts = e.get('ts', '?')[11:19]  # HH:MM:SS
        etype = e.get('type', '?')
        data = e.get('data', {})

        if etype == 'tool_call':
            cmd = data.get('command', '')[:80]
            print(f'[{ts}] TOOL: {cmd}')
        elif etype == 'turn_start':
            print(f'[{ts}] TURN {data.get(\"turn\", \"?\")}')
        elif etype.startswith('stream_'):
            # Stream events - show interesting ones
            sub = etype.replace('stream_', '')
            if 'function' in sub.lower() or 'tool' in sub.lower():
                name = data.get('name', data.get('raw', ''))[:60]
                print(f'[{ts}]   -> {sub}: {name}')
            elif 'text' in sub.lower() or 'message' in sub.lower():
                txt = data.get('raw', data.get('text', ''))[:100]
                if txt:
                    print(f'[{ts}]   <- {sub}: {txt}')
        elif etype == 'finding':
            sev = data.get('severity', '?')
            title = data.get('title', data.get('description', 'unknown'))
            print(f'[{ts}] *** FINDING [{sev}]: {title} ***')
        elif etype == 'question':
            print(f'[{ts}] QUESTION: {data.get(\"question\", \"\")}')
        elif etype == 'scan_start':
            print(f'[{ts}] SCAN STARTED: {data.get(\"targets\", [])}')
        elif etype == 'scan_complete':
            print(f'[{ts}] SCAN COMPLETE')
            break
        elif etype == 'instruction_received':
            print(f'[{ts}] INSTRUCTION: {data.get(\"instruction\", \"\")[:80]}')
    except json.JSONDecodeError:
        pass
    sys.stdout.flush()
"
