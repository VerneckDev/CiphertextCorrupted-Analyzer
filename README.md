# Ciphertext/Corrupted data Analyzer

A toolkit of two standalone Python scripts for inspecting suspected ciphertext and diagnosing corruption or tampering between two versions of the same byte sequence. Neither script decrypts anything: they work purely on statistical properties, structural patterns, and byte-by-byte comparison to help you decide *what* might be wrong with a file before you try to fix it.

The project has two independent tools:

1. **`analyzer.py`** — a single-file (or multi-file) **statistical/heuristic analyzer**: entropy, chi-square, index of coincidence, repeated-block detection, padding checks, magic-number detection, and a confidence-scored guess at what kind of data you're looking at.
2. **`diff_find.py`** — a **byte-level forensic diff** between a known-good ("raw") byte sequence and a suspect ("encrypted") one: it classifies each difference as a position swap, a permutation chain, a simple value change, or (for files of different length) a move/insertion/deletion.

> **Note on input formats:** the two scripts expect different inputs. `analyzer.py` reads files **as raw binary**. `diff_find.py` reads files **as text containing hexadecimal byte values** separated by whitespace/newlines (e.g. `4a 3f 01 ff …`), one byte per token. Feeding a raw binary file to `diff_find.py`, or a hex-text file to `analyzer.py`, will not work as expected.

---

## Repository structure

```
Ciphertext-Corrupted-Analyzer/
├── analyzer.py    # Statistical/heuristic analysis of one or more binary files
├── diff_find.py       # Byte-level diff between two hex-text files (raw vs. encrypted/corrupted)
└── README.md
```

No third-party cryptography library is used. `analyzer.py` relies only on the Python standard library (`matplotlib` is optional, only for `--histogram`). `diff_find.py` relies only on the standard library (`difflib` for sequence alignment when file sizes differ).

---

## Requirements

- Python 3.9+ (uses `int.bit_count()` in `analyzer.py`, added in Python 3.10, and `from __future__ import annotations`).
- Optional, only for `analyzer.py --histogram`:

```bash
python -m pip install matplotlib
```

---

## How it works

### 1. `analyzer.py` — statistical/heuristic analyzer

For each input file, the script computes a set of metrics and combines them into a heuristic classification. It does **not** and **cannot** definitively identify an algorithm (AES, RSA, etc.) — it only reports evidence.

| Metric / check | What it measures |
|---|---|
| Shannon entropy (bits/byte) | Randomness of the byte distribution; ciphertext/compressed data trends toward 8.0 |
| Normalized entropy | Entropy relative to the maximum observable for the sample size (useful for short files) |
| Chi-square vs. uniform | How far the byte distribution deviates from a perfectly uniform one |
| Index of coincidence (IC) | Probability that two random bytes are equal; random data has IC ≈ 1/256 |
| Serial correlation (lag 1) | Linear correlation between adjacent bytes |
| Printable / UTF-8 ratio | Share of the content that looks like readable text |
| ASCII string extraction | Runs of ≥4 printable characters, with offsets |
| Magic-number detection | Known file signatures (PNG, PDF, ZIP, gzip, ELF, etc.) found anywhere in the file |
| 16-byte block repetition | Repeated blocks are a strong signal of a deterministic mode (e.g. ECB) |
| Repeated 4-gram / 8-gram | Shorter repeated byte sequences, for finer-grained pattern detection |
| Padding checks | PKCS#7, ANSI X.923, ISO/IEC 7816-4, and zero padding, flagged as unreliable unless `--plaintext` is set |
| Block-size alignment | Whether the file size is a multiple of 8, 16, or 24 bytes (common block-cipher sizes) |

When two or more files are analyzed with `--compare`, it additionally reports, for every pair:

- Byte-by-byte differences and contiguous difference "runs".
- XOR of the overlapping region (entropy, zero-byte ratio, longest run of identical bytes).
- Hamming distance/ratio between the two byte sequences.
- Identical 16-byte blocks shared at the same or different positions.
- Automatic flags (e.g. "Hamming distance below what's expected for independent random sequences", useful for spotting keystream/nonce reuse).

### 2. `diff_find.py` — byte-level forensic diff

Given a **raw (reference)** file and an **encrypted/suspect** file, both encoded as whitespace-separated hex bytes, the script compares them byte by byte and classifies every difference into one of these categories:

- **Swaps** — exactly two positions where the bytes have traded places (`raw[i] == encrypted[j]` and `raw[j] == encrypted[i]`), detected via a union-find grouping of related differences.
- **Permutation chains** — three or more positions whose values got cyclically shuffled among each other.
- **Modifications** — a byte changed to a value that isn't explained by a swap or chain with any other differing position.
- **Moves / deletions / insertions** — only computed when the two files have **different lengths**, using `difflib.SequenceMatcher` to align the sequences and classify each "replace"/"delete"/"insert" opcode.

The script writes two output files next to the encrypted file:

- `<name>_relatorio.txt` — a human-readable report listing every swap, chain, modification, move, deletion, and insertion found.
- `<name>_corrigido.dat` — the reference (`raw`) byte sequence written back out in hex-text format, as a "known-good" copy to compare against or restore from.

Any previous copies of these two files are deleted before a new run, so re-running the script always reflects the latest comparison.

---

## Usage

### `analyzer.py`

```bash
# Basic report for one file
python analyzer.py suspicious.bin

# Verbose report (byte frequency table, ASCII strings, n-grams)
python analyzer.py suspicious.bin -v

# Compare two or more files pairwise
python analyzer.py file_a.bin file_b.bin -c

# Treat the input as known plaintext (padding checks become meaningful)
python analyzer.py plaintext.bin -pl

# Machine-readable output
python analyzer.py suspicious.bin -j > report.json

# Also generate a byte-frequency histogram PNG
python analyzer.py suspicious.bin -hst
```

| Flag | Description |
|---|---|
| `files` | One or more files to analyze (positional) |
| `-c`, `--compare` | Compare every pair of input files |
| `-v`, `--verbose` | Show byte-frequency table, ASCII strings, and n-grams |
| `-pl`, `--plaintext` | Treat input as plaintext when checking padding |
| `-j`, `--json` | Output JSON instead of the text report |
| `-hst`, `--histogram` | Generate a byte-frequency histogram PNG (requires `matplotlib`) |

### `diff_find.py`

Both input files must be text files containing hex byte values separated by whitespace or newlines:

```
4a 3f 01 ff 00 9c ...
```

Run:

```bash
python diff_find.py raw.dat encrypted.dat
```

> The script's own `--help`-style usage message refers to it as `comparar.py` — this is left over from an earlier filename; the actual entry point in this repository is `diff_find.py`, and that's what should be used on the command line.

Output:

- A console summary (file sizes, first bytes, raw difference list, and totals per category).
- `encrypted_relatorio.txt` — the detailed report (or `encrypted<...>_relatorio.txt` for whatever the encrypted file's base name is).
- `encrypted_corrigido.dat` — the raw sequence re-written in hex-text format.

---

## Implementation notes

- **`analyzer.py` classification is heuristic only.** High entropy plus a low index of coincidence is consistent with encryption or compression, but the script cannot and does not claim to identify a specific cipher or mode. Every classification result includes a `warnings` list and `definitive_algorithm_identification: false`.
- **Padding checks on ciphertext are inherently unreliable.** A coincidental byte pattern can look like valid PKCS#7/X.923/ISO 7816-4/zero padding by chance; `analyzer.py` labels these checks `not_reliable_on_ciphertext` unless `--plaintext` is passed.
- **`diff_find.py`'s swap/chain detection is O(n²)** over the number of differing bytes (it compares every pair of differences to build the union-find groups), so it can become slow on files with a very large number of differing positions.
- **The `_corrigido.dat` file is not a repair of the encrypted file** — it is simply the `raw` reference re-serialized to hex text. It's meant as a convenient "known-good" copy alongside the report, not an automatic fix derived from the diff.

## Known issues / limitations

This project is **experimental**; treat both scripts as diagnostic aids, not authoritative answers:

- **`diff_find.py` crashes on same-length files with differing bytes.** `comparison()` builds each difference record with the keys `"indice"` and `"posicao"`, but `changes()`, and the swap/chain branches inside `detc_groups()`, read them back as `"index"` and `"position"` — a `KeyError` on the first run that finds any differing byte. Until this is fixed, same-length comparisons (the script's main path) will not complete.
- **`analyzer.py` cannot identify a specific algorithm.** High entropy is compatible with many ciphers, compressed formats, and random data alike; use the candidates list as a starting point for further investigation, not a conclusion.
- **Short files limit every statistical test.** With fewer than ~256 bytes, entropy and chi-square lose most of their discriminating power; `analyzer.py` surfaces this with explicit warnings, but the caller still has to account for it.
- **`diff_find.py`'s move/insertion/deletion detection (`difflib`-based) is a heuristic alignment**, not a guaranteed reconstruction of what actually happened to the data — `SequenceMatcher` finds *a* plausible alignment, not necessarily *the* one that occurred.

---

## Author

**João Pedro Verneck** — [@VerneckDev](https://github.com/VerneckDev)

## References

- [Python `difflib` documentation](https://docs.python.org/3/library/difflib.html) — used by `diff_find.py` for sequence alignment on length-mismatched files.
- [Shannon entropy / index of coincidence — classical cryptanalysis statistics](https://en.wikipedia.org/wiki/Index_of_coincidence) — background for the metrics in `analyzer.py`.
- [PKCS#7 padding (RFC 5652)](https://www.rfc-editor.org/rfc/rfc5652) — one of the padding schemes checked by `analyzer.py`.