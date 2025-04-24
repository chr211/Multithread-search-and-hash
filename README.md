# Multi‑Process File System Search & Hashing Tool

> **Version 1.2** – Parallelized file search with metadata & SHA‑256 hashing

## Overview

This Python script is a small forensic‑oriented utility that **recursively walks a directory tree, records detailed file metadata, calculates SHA‑256 hashes, and offers fast, multi‑process search functions**.  It began as an academic exercise (HW #4) and has since been refactored for real‑world incident response where reducing search time across large file systems is critical.

---

## Key Features

| Feature                       | Description                                                                                                                                      |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Recursive enumeration**     | Uses `os.walk()` to collect every file under a user‑selected root.                                                                               |
| **Rich metadata capture**     | Stores file size plus MAC times (Modified, Accessed, Created) converted to UTC.                                                                  |
| **SHA‑256 hashing**           | Calculates cryptographic hashes for integrity verification or IOC matching; progress indicator included.                                         |
| **Four search modes**         | 1 = exact filename • 2 = file extension • 3 = SHA‑256 hash • 4 = string within file (parallel).                                                  |
| **True parallel text search** | Leverages `multiprocessing.Pool` sized to `cpu_count()` and a dedicated helper module `multiSearchWithinFile` to scan file contents in parallel. |
| **PrettyTable reporting**     | Human‑readable tabular output, automatically sorted by file size.                                                                                |
| **Interactive menu**          | Lightweight TUI for directory changes, hash generation, and result printing without restarting the program.                                      |

---

## Installation

```bash
# Python ≥3.8 recommended
pip install prettytable
```

> No other third‑party dependencies are required.

---

## Usage

1. **Run the script**
   ```bash
   python file_search_tool.py
   ```
2. **Select the root directory** when prompted (e.g. `C:/` or `/mnt/data`).
3. **Choose an option** from the menu:
   ```text
   1. Find a file by name (case‑insensitive)
   2. Find all files by type (extension)
   3. Find file by hash value (SHA‑256)
   4. Find file containing text string
   5. Calculate hashes for current directory tree
   6. Change root directory
   7. Print current tree contents
   8. Print current tree root
   0. Exit
   ```
4. **Review results** – search output is displayed in a formatted table; MAC times are shown in UTC.

### Example session

```text
Enter Directory Path i.e. c:/ >>>: /evidence_drive
...
4. Find file containing text string.
Enter search term: secret_key=123
Please wait...
Found 12 files.
+--------------------------------------------------+-----------+---------------------+---------------------+---------------------+
| File Name                                        | File Size | Modified            | Accessed            | Created             |
+--------------------------------------------------+-----------+---------------------+---------------------+---------------------+
| /evidence_drive/config/app.conf                  | 4.1 KB    | 2025‑04‑20 17:53:22 | 2025‑04‑22 12:05:10 | 2025‑04‑20 17:53:22 |
| ... (other matches)                              |           |                     |                     |                     |
+--------------------------------------------------+-----------+---------------------+---------------------+---------------------+
Time taken: 0.42 seconds.
```

---

## How It Works

- **Directory enumeration** builds a list of absolute file paths.
- **`GetFileMetaData()`** gathers size + MAC times via `os.stat()`.
- **`HashFiles()`** reads each file once and appends a SHA‑256 digest to the metadata list.
- **Search engine**
  - Modes 1‑3 iterate over the metadata list with simple comparisons or regex.
  - **Mode 4** uses `multiprocessing.Pool` to spawn workers equal to the number of CPU cores; each worker executes `multiSearchWithinFile.searchWithinFile()` on its assigned file slice, returning a match list.

The design cleanly separates heavy I/O work (hashing, content search) from metadata collection, keeping interactive tasks responsive.

---

## Design Rationale

- **Forensic readiness** – hashing and MAC time capture provide an evidentiary chain.
- **Speed** – text searches scale linearly with core count, making it viable for large evidence sets.
- **Modularity** – core search logic lives in `multiSearchWithinFile.py`, simplifying unit testing and future improvements (e.g., regex or fuzzy search).

---

## Limitations & Future Work

- Currently loads entire files into memory when hashing; large files may impact RAM.
- Text search is byte‑wise and case‑sensitive; adding regex / case‑insensitive modes is planned.
- No exclusion filters (e.g., skip system paths) – could be added via CLI flags.
- Lacks automated tests; converting helper functions to pytest + CI would improve robustness.

---

## Contributing

Pull requests are welcome!  Please open an issue first to discuss significant changes.

---

## License

Distributed under the **MIT License** (see LICENSE for details).

---

## Credits

- **Christopher O’Brien** – original author & enhancements.
- Inspired by examples from *FirstScript.py* and *WalkFileSystem.py* by **Chet Hosmer**.
