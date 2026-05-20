#!/usr/bin/env python3
"""
Extract a structured view of the Claude Code session for Q4 curation.
Pulls human turns and substantive assistant text turns, skips raw tool results.
"""
import json
from pathlib import Path

SESSION = Path(__file__).parent / "q4-session.jsonl"
OUTPUT = Path(__file__).parent / "q4-session-extracted.md"

events = []
with open(SESSION) as f:
    for i, line in enumerate(f, 1):
        try:
            obj = json.loads(line)
            events.append((i, obj))
        except:
            pass

print(f"Total events: {len(events)}")

# Categorize
human_turns = []
assistant_text_turns = []
tool_uses = []  # (line, name, input_summary)

for line_no, obj in events:
    if obj.get("type") == "user":
        msg = obj.get("message", {})
        content = msg.get("content", "")
        if isinstance(content, str) and content.strip():
            human_turns.append({"line": line_no, "ts": obj.get("timestamp"), "text": content})
    elif obj.get("type") == "assistant":
        msg = obj.get("message", {})
        content = msg.get("content", [])
        if isinstance(content, list):
            for block in content:
                if block.get("type") == "text":
                    text = block.get("text", "")
                    if text.strip():
                        assistant_text_turns.append({"line": line_no, "ts": obj.get("timestamp"), "text": text})
                elif block.get("type") == "tool_use":
                    name = block.get("name", "")
                    inp = block.get("input", {})
                    summary = ""
                    if name == "Read":
                        summary = inp.get("file_path", "")
                    elif name == "Write":
                        summary = inp.get("file_path", "")
                    elif name == "Edit":
                        summary = inp.get("file_path", "")
                    elif name == "Bash":
                        summary = inp.get("command", "")[:120]
                    elif name == "Grep":
                        summary = f"pattern: {inp.get('pattern', '')[:80]}"
                    elif name == "Glob":
                        summary = f"glob: {inp.get('pattern', '')[:80]}"
                    elif name == "TodoWrite":
                        todos = inp.get("todos", [])
                        summary = f"{len(todos)} todos"
                    else:
                        summary = str(inp)[:100]
                    tool_uses.append({"line": line_no, "ts": obj.get("timestamp"), "name": name, "summary": summary})

print(f"Human turns: {len(human_turns)}")
print(f"Assistant text turns: {len(assistant_text_turns)}")
print(f"Tool uses: {len(tool_uses)}")
print()

# Build a chronological merged view: human turns + assistant text turns + tool use counts between them
all_events = []
for h in human_turns:
    all_events.append(("HUMAN", h["line"], h["ts"], h["text"]))
for a in assistant_text_turns:
    all_events.append(("ASSISTANT", a["line"], a["ts"], a["text"]))
for t in tool_uses:
    all_events.append(("TOOL", t["line"], t["ts"], f"{t['name']}: {t['summary']}"))

all_events.sort(key=lambda x: x[1])

# Group: for each HUMAN turn, list the next phase until the next HUMAN turn
human_lines = [h["line"] for h in human_turns]
phases = []
for i, h_line in enumerate(human_lines):
    end = human_lines[i+1] if i+1 < len(human_lines) else 99999
    phase_events = [e for e in all_events if h_line <= e[1] < end]
    phases.append({"human_line": h_line, "events": phase_events})

# Write extraction
with open(OUTPUT, "w") as out:
    out.write("# Q4 Session — Raw Extraction\n\n")
    out.write(f"Session: aa050252-d44c-4908-8b16-cd2897f69a6c\n")
    out.write(f"Project: /Users/omsatyaswaroop/Downloads/sentinelflow\n")
    out.write(f"Branch: main\n")
    out.write(f"Total events: {len(events)} | Human turns: {len(human_turns)} | Assistant text turns: {len(assistant_text_turns)} | Tool uses: {len(tool_uses)}\n\n")
    out.write("---\n\n")
    for phase_idx, phase in enumerate(phases, 1):
        out.write(f"\n## Phase {phase_idx} (starts at line {phase['human_line']})\n\n")
        tool_count_by_name = {}
        for kind, line, ts, text in phase["events"]:
            if kind == "TOOL":
                name = text.split(":")[0]
                tool_count_by_name[name] = tool_count_by_name.get(name, 0) + 1
            elif kind == "HUMAN":
                out.write(f"### >> HUMAN [L{line} | {ts}]\n\n")
                out.write(text.strip() + "\n\n")
            elif kind == "ASSISTANT":
                out.write(f"### <- ASSISTANT [L{line} | {ts}]\n\n")
                out.write(text.strip() + "\n\n")
        if tool_count_by_name:
            tool_summary = ", ".join(f"{n}×{c}" for n, c in tool_count_by_name.items())
            out.write(f"*Tool calls in this phase: {tool_summary}*\n\n")

print(f"Written to {OUTPUT}")
