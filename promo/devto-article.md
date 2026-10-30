# I Open-Sourced a System Prompt That Turns Any LLM into a Reverse-Engineering Assistant

If you've ever tried to use ChatGPT / Claude / DeepSeek / GLM for binary analysis, you know the pain:

- It **hallucinates APIs and offsets** ("this function calls `CheckRemoteDebuggerPresent` at 0x4012A0" — no it doesn't)
- It gives **surface-level textbook answers** instead of a real analysis workflow
- Every session starts from zero — no structure, no methodology

So I built **ZETA CYBERLAB V5.0** — a single, production-ready system prompt that fixes this. It's open source and MIT licensed:

**→ https://github.com/fanximing111/Reverse-Engineering-Assistant-Prompt**

## What it does

Paste the prompt into your model's system prompt slot (Custom Instructions, Claude Projects, assistant persona — anything that accepts one), and the model becomes "Zo": a senior reverse engineer with a fixed methodology.

It ships with 12 modules:

1. **Binary Analysis Engine** — PE32/PE32+, ELF, Mach-O: headers, sections, IAT/EAT, relocations, TLS callbacks
2. **Assembly & Decompilation** — x86/x64/ARM/ARM64, calling conventions (cdecl/stdcall/SysV/AAPCS), stack frames, SIMD, pseudo-code reconstruction
3. **Dynamic Debugging** — x64dbg, WinDbg, GDB, LLDB, IDA, Ghidra, Binary Ninja; breakpoint selection strategy included
4. **Protection Analysis** — packers (UPX & custom), control-flow flattening, VM-based protection, anti-debug techniques (PEB checks, RDTSC), integrity checks
5. **License System Design Audit** — from a *defensive* perspective: signature schemes, device binding, token lifecycle, hardening advice
6. **Memory & Runtime** — VTable/object layout, ASLR/DEP/Canary/CFG
7. **Tool Development** — Capstone, Keystone, Unicorn, LIEF, pefile, Frida, angr, YARA, Ghidra API
8. **Patching & Compatibility** — binary diff, hot patching, ABI issues
9. **Automated 7-Step Workflow** — identification → structure → static → dynamic → logic reconstruction → validation → report
10. **Standardized Output Format** — every complex answer comes as: target analysis / principles / process / code / run instructions / verification / troubleshooting / conclusions
11. **Research Integrity (the important one)**
12. **Expert Modes** — auto-switches between static / dynamic / packer / tooldev modes per task

## The anti-hallucination module is the real gem

Module 11 is mandatory and specifically targets LLM failure modes in this domain:

- ❌ Never fabricate disassembly output
- ❌ Never fake debugger output or pretend code was executed
- ❌ Never invent functions/APIs that don't exist
- ✅ Unverified conclusions must be explicitly labeled as speculation
- ✅ Missing files/logs → say so, state assumptions upfront
- ✅ Unauthorized key extraction / access-control bypass → refuse, pivot to defensive analysis

This makes the difference between "confident nonsense" and an assistant that actually tells you *what it verified vs. what it's guessing* — which is exactly what you need when reading a disassembly at 2 AM.

## Example: what a session looks like

You paste:

> Here's a Ghidra decompilation of a function from my own tool, it crashes when input length > 64. `[paste pseudocode]`

The assistant automatically enters the workflow: identifies what it can verify from the code, walks through stack frame analysis, pinpoints the suspect buffer handling, labels each claim as fact/speculation, and ends with concrete steps to validate in x64dbg (breakpoint location + what to watch).

## Legal / ethical note

The prompt is scoped to **legitimate scenarios only**: your own software, authorized assessments, CTF challenges, isolated lab environments, and defensive research. It explicitly instructs the model to refuse unauthorized license bypass or credential extraction. Use it within your local laws and the target software's license terms.

## Get it

⭐ Repo: https://github.com/fanximing111/Reverse-Engineering-Assistant-Prompt

Copy `ZETA-CYBERLAB-V5-prompt.md` → paste into your system prompt → done. MIT licensed, contributions welcome.

What would you add to it? Issues and PRs are open.

---

*Tags: reverse engineering, LLM, system prompt, binary analysis, CTF*
