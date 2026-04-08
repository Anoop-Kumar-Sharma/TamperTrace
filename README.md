# TamperTrace

TamperTrace is a Windows-based memory analysis and integrity inspection tool designed to detect byte-level modifications in running processes.

It scans process memory, extracts dynamically referenced regions, and highlights potentially altered or suspicious data through targeted hex dumps.

---

# 📌 Overview

Modern applications frequently manipulate memory at runtime, making it difficult to identify unauthorized modifications or hidden behavior. TamperTrace provides a low-level view into process memory, allowing developers and security researchers to inspect how memory is structured and whether it has been altered.

Unlike simple scanners, TamperTrace does not just dump memory blindly—it actively searches for structured references to memory regions and inspects those regions for analysis.

---

# 🔍 Key Features

### 🧠 Memory Scanning Engine

* Traverses full virtual address space of target processes
* Uses `VirtualQueryEx` to safely enumerate memory regions
* Filters only committed and readable memory

### ⚡ Multi-threaded Performance

* Splits memory scanning across multiple threads
* Efficient chunk-based reading for large address spaces
* Optimized for high-speed analysis

### 🔎 Pattern Detection

* Scans UTF-16 memory for structured patterns like:

  ```
  process.exe (PID) (0xSTART - 0xEND)
  ```
* Extracts process names, PIDs, and memory ranges

### 🧾 Targeted Memory Dumping

* Reads extracted memory regions using `ReadProcessMemory`
* Outputs:

  * Hexadecimal byte view
  * ASCII representation
* Limits dump size for performance and readability

### 🛡️ Alteration Detection (Manual Analysis)

* Helps identify unusual or modified memory regions
* Enables comparison and investigation of byte-level changes

---

# ⚙️ Architecture

## 1. Process Enumeration

* Uses ToolHelp32 APIs to locate processes by name
* Supports scanning multiple instances

## 2. Memory Traversal

* Iterates from `lpMinimumApplicationAddress` to `lpMaximumApplicationAddress`
* Uses `VirtualQueryEx` to inspect each region

## 3. Memory Reading

* Reads memory in chunks (default: 1MB)
* Skips inaccessible or protected regions

## 4. Pattern Extraction

* Converts raw memory into UTF-16
* Applies regex-based pattern matching

## 5. Region Extraction & Dumping

* Parses detected memory ranges
* Reads and prints selected bytes in hex format

---

# 🛠️ Build Instructions

## Requirements

* Windows 10/11
* C++ Compiler (MSVC / MinGW)
* Administrator privileges (recommended)

## Build (MinGW)

```bash
g++ main.cpp -o TamperTrace.exe -static -O2
```

## Build (Visual Studio)

1. Create a new Console Application
2. Add source code
3. Set configuration to Release
4. Build solution

---

# 🚀 Usage

Run the tool as Administrator:

```bash
TamperTrace.exe
```

### Default Behavior

* Targets predefined processes (e.g., `dwm.exe`, `explorer.exe`)
* Scans memory regions
* Prints detected references
* Dumps relevant memory blocks

### Example Output

```
Process --> dwm.exe
PID --> 3000
Memory Range --> 0x15c8785c000 - 0x15c8799a000

Address        Hex Dump                                  ASCII
--------------------------------------------------------------
0x15c8785c000  48 8B 05 ...                              H...
...
```

---

# ⚠️ Limitations

### 🔒 Protected Processes (PPL)

* Cannot read memory of protected processes like `dwm.exe` (in some configurations)
* Even with debug privileges, access may be denied

### 🧩 Memory Volatility

* Memory may change during scanning
* Extracted addresses may become invalid

### 🚫 Partial Reads

* Some regions may return partial or failed reads

### 🧠 Detection Scope

* Does not automatically confirm malicious behavior
* Requires manual analysis for interpretation

---

# 🧠 Use Cases

* Reverse engineering
* Debugging runtime memory issues
* Analyzing memory structures
* Detecting runtime patches or hooks
* Security research and anti-tamper exploration

---

# 🔧 Possible Improvements

* Automatic baseline comparison (true tamper detection)
* Hash-based integrity verification
* Module-level scanning
* Hook detection (IAT/EAT/inline)
* Kernel-mode support for protected processes

---

# 📌 Notes

TamperTrace is a research-oriented tool. It exposes raw memory data and highlights potentially interesting regions, but interpretation is left to the user.

---

# 📄 License

This project is intended for educational and research purposes only.

Use responsibly.
