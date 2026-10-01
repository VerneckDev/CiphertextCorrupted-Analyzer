#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import math
import os
import re
import statistics
from collections import Counter, defaultdict
from itertools import combinations
from pathlib import Path
from typing import Any, Dict, List, Tuple


BLOCK_SIZE = 16 # Standard block size for AES and other block ciphers in bytes
RANDOM_BYTE_ENTROPY = 8.0 # Maximum entropy for a single byte (8 bits)
EXPECTED_RANDOM_IC = 1.0 / 256.0 # Expected index of coincidence (IC) for random byte sequences

MAGIC_SIGNATURES = [ # Common file signatures (magic numbers) for identifying file types, describe the file format based on the first few bytes of the file
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"%PDF", "PDF document"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"PK\x05\x06", "ZIP archive (empty)"),
    (b"PK\x07\x08", "ZIP archive (spanned)"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"BM", "BMP image"),
    (b"RIFF", "RIFF container (AVI/WAV/etc.)"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "XZ"),
    (b"7z\xbc\xaf'\x1c", "7-Zip archive"),
    (b"Salted__", "OpenSSL salted format"),
    (b"\x85\x02", "GPG/PGP packet"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"\x7fELF", "ELF executable"),
    (b"MZ", "PE/DOS executable"),
]

PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,}") # Compile a regex pattern to match sequences of printable ASCII characters (4 or more in length)


def entropy(data: bytes) -> float:

    if not data:

        return 0.0 # Detects empty input and returns an entropy of 0.0
    
    freq = Counter(data) # Count the frequency of each byte value in the input data
    n = len(data) # Get the total number of bytes in the input data

    return -sum((c / n) * math.log2(c / n) for c in freq.values()) # Calculate the Shannon entropy using the formula: H(X) = -sum(p(x) * log2(p(x))) for each unique byte value, where p(x) is the probability of that byte value occurring in the data


def entropy_norm(data: bytes) -> float:

    n = len(data)

    if n <= 1:

        return 0.0 # Detects input with 1 or fewer bytes and returns a normalized entropy of 0.0
    
    entropy_max = math.log2(min(n, 256)) # Uses the minimum of the length of the data and 256 to calculate the maximum possible entropy for the given data length

    return entropy(data) / entropy_max if entropy_max else 0.0 # Returns the normalized entropy by dividing the calculated entropy by the maximum possible entropy, ensuring that the result is between 0 and 1


def chi_sq(data: bytes) -> float:

    if not data:

        return 0.0 # Detects empty input and returns a chi-square value of 0.0
    
    freq = [0] * 256 # Initialize a list of 256 zeros to count the frequency of each possible byte value (0-255)

    for b in data:

        freq[b] += 1

    freq_expe = len(data) / 256.0 # Calculate the expected frequency for each byte value if the data were uniformly distributed

    return sum((obs - freq_expe) ** 2 / freq_expe for obs in freq) # Chi-square statistic: sum of (observed - expected)^2 / expected across all 256 possible byte values; higher values mean the byte distribution deviates more from uniform


def calculate_ic(data: bytes) -> float:

    n = len(data)

    if n < 2:

        return 0.0 # Detects input with fewer than 2 bytes and returns an index of coincidence of 0.0
    
    freq = Counter(data)

    return sum(c * (c - 1) for c in freq.values()) / (n * (n - 1)) # Calculates the index of coincidence using the formula: IC = sum(c * (c - 1)) / (n * (n - 1)), where c is the frequency of each unique byte value and n is the total number of bytes in the data. This measures how likely it is that two randomly selected bytes from the data are the same.


def serial_corr(data: bytes, lag: int = 1) -> float:

    if len(data) <= lag:

        return 0.0 # Detects input with length less than or equal to the specified lag and returns a serial correlation of 0.0

    x = [float(v) for v in data[:-lag]] # Create a list of float values from the input data, excluding the last 'lag' bytes
    y = [float(v) for v in data[lag:]]
    mx = statistics.mean(x) # Mean of the x series (bytes at position i)
    my = statistics.mean(y) # Mean of the y series (bytes at position i + lag)

    num = sum((a - mx) * (b - my) for a, b in zip(x, y)) # Calculate the numerator of the serial correlation formula, which is the sum of the products of the deviations of each pair of corresponding values in x and y from their respective means
    den_x = math.sqrt(sum((a - mx) ** 2 for a in x)) # Calculate the denominator for x, which is the square root of the sum of the squared deviations of each value in x from its mean
    den_y = math.sqrt(sum((b - my) ** 2 for b in y))

    if den_x == 0 or den_y == 0:

        return 0.0 # Detects if either denominator is zero (which would indicate no variation in the data) and returns a serial correlation of 0.0 to avoid division by zero
    
    return num / (den_x * den_y) # Returns the serial correlation coefficient, which measures the linear relationship between the values in the data separated by the specified lag. A value close to 1 indicates a strong positive correlation, while a value close to -1 indicates a strong negative correlation


def byte_freq(data: bytes) -> List[Tuple[int, int]]:

    return sorted(Counter(data).items(), key=lambda x: (-x[1], x[0])) # Calculate the frequency of each byte value in the input data using a Counter, and return a sorted list of tuples (byte_value, count) in descending order of count, and ascending order of byte value for ties


def print_ratio(data: bytes) -> float:

    if not data:

        return 0.0 # Detects empty input and returns a printable ratio of 0.0
    
    return sum(32 <= b <= 126 for b in data) / len(data) # Returns the ratio of printable ASCII characters (byte values between 32 and 126 inclusive) to the total number of bytes in the input data


def utf8_ratio(data: bytes) -> float:

    if not data:

        return 0.0
    
    try:

        text = data.decode("utf-8") # Try to decode the input data as UTF-8 text

    except UnicodeDecodeError:

        return 0.0 # If decoding fails, return a UTF-8 ratio of 0.0
    
    if not text:

        return 0.0 # Detects an empty decoded string and returns a UTF-8 ratio of 0.0
    
    return sum(ch.isprintable() or ch in "\r\n\t" for ch in text) / len(text) # Calculate the ratio of printable characters (including whitespace characters like carriage return, newline, and tab)


def ascii_str(data: bytes, minimum: int = 4) -> List[Dict[str, Any]]:

    strs = []

    for match in re.finditer(rb"[\x20-\x7e]{%d,}" % minimum, data): # Finditer returns an iterator yielding match objects for all non-overlapping matches of the regex pattern in the input data

        raw = match.group() # Get the matched byte sequence from the match object
        
        try:

            value = raw.decode("ascii") # Try to decode the matched byte sequence as ASCII text

        except UnicodeDecodeError:

            continue

        strs.append({"offset": match.start(), "length": len(raw), "text": value}) # Append a dictionary containing the offset, length, and decoded text of the matched ASCII string to the list of strings

    return strs # Return the list of dictionaries representing the detected ASCII strings in the input data


def detect_magic(data: bytes) -> List[Dict[str, Any]]:

    found = []

    for signature, description in MAGIC_SIGNATURES:

        start = 0

        while True:

            pos = data.find(signature, start) # Search for the next occurrence of this signature, starting the search at 'start'

            if pos < 0:

                break # No further occurrences of this signature; move on to the next one

            found.append({"offset": pos, "magic_hex": signature.hex(), "description": description}) # Append a dictionary containing the offset, hexadecimal representation of the magic signature, and its description to the list of found magic numbers

            start = pos + 1 # Resume searching right after this match (so overlapping/repeated occurrences can still be found)

    return sorted(found, key=lambda x: x["offset"]) # Return the list of found magic numbers sorted by their offset in the input data


def full_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> List[bytes]:

    n = len(data) // block_size # Calculate the total number of full blocks of the specified block size that can be formed from the input data

    return [data[i * block_size:(i + 1) * block_size] for i in range(n)] # Slice the data into non-overlapping chunks of block_size bytes; any incomplete trailing block shorter than block_size is discarded


def reptd_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> Dict[str, Any]:

    blocks = full_blocks(data, block_size)
    total = len(blocks)
    counter = Counter(blocks)
    repeated_groups = {b: c for b, c in counter.items() if c > 1} # Keep only the distinct blocks that occur more than once

    pos = []

    for block, count in repeated_groups.items():

        pos_list = [i for i, candidate in enumerate(blocks) if candidate == block] # Find every block index where this repeated block value occurs
        pos.append({"block_hex": block.hex(), "count": count, "positions": pos_list})

    repeated_block_instances = sum(c - 1 for c in counter.values() if c > 1) # Calculate the total number of repeated block instances by summing the excess occurrences of each block
    repeat_rate = repeated_block_instances / total if total else 0.0 # Calculate the repeat rate as the ratio of repeated block instances to the total number of blocks

    return {

        "block_size": block_size,
        "full_blocks": total,
        "ignored_tail_bytes": len(data) % block_size,
        "unique_blocks": len(counter),
        "repeated_groups": len(repeated_groups),
        "repeated_block_instances": repeated_block_instances,
        "repeat_rate": repeat_rate,
        "details": sorted(pos, key=lambda x: (-x["count"], x["positions"][0])),

    }


def reptd_ngrams(data: bytes, n: int = 4, max_items: int = 20) -> List[Dict[str, Any]]:

    if len(data) < n:

        return []

    counter = Counter(data[i:i + n] for i in range(len(data) - n + 1)) # Count occurrences of every n-byte sliding window (n-gram) found in the data
    result = []

    for gram, count in counter.most_common():

        if count < 2:

            break # most_common() is sorted in descending order of count, so once count drops below 2 there are no more repeated n-grams left to report

        pos = [i for i in range(len(data) - n + 1) if data[i:i + n] == gram] # Find all starting positions of the n-gram in the input data
        result.append({"n": n, "hex": gram.hex(), "count": count,"positions": pos[:20]}) # Append a dictionary containing the n-gram size, hexadecimal representation of the n-gram, its count, and the first 20 positions to the result list

        if len(result) >= max_items:

            break

    return result


def hamm_dist(a: bytes, b: bytes) -> int:

    return sum((x ^ y).bit_count() for x, y in zip(a, b)) # Calculate the Hamming distance between two byte sequences by XORing corresponding bytes and counting the number of differing bits


def xor_bytes(a: bytes, b: bytes) -> bytes:

    return bytes(x ^ y for x, y in zip(a, b)) # Return a new byte sequence resulting from the XOR operation between corresponding bytes of two input byte sequences


def zeros_line(data: bytes) -> Tuple[int, int]:

    best_len = 0
    best_start = -1
    start = None

    for i, b in enumerate(data):

        if b == 0:

            if start is None:

                start = i # Mark the start of a new run of consecutive zero bytes

            current = i - start + 1 # Length of the current run of zero bytes ending at position i

            if current > best_len:

                best_len = current
                best_start = start

        else:

            start = None # A non-zero byte breaks the current run of zeros

    return best_len, best_start # Return the length and starting index of the longest contiguous sequence of zero bytes in the input data


def pkcs7_chk(data: bytes, block_size: int = BLOCK_SIZE) -> Dict[str, Any]:

    if not data:

        return {"valid": False, "reason": "empty data"}
    
    if len(data) % block_size != 0:

        return {"valid": False, "reason": "length is not a multiple of block size"}

    p = data[-1]

    if not 1 <= p <= block_size:

        return {"valid": False, "reason": f"last byte is {p}, outside 1..{block_size}"} # Check if the last byte of the data is within the valid range for PKCS#7 padding (1 to block_size)

    if data[-p:] == bytes([p]) * p:

        return {"valid": True, "padding_bytes": p} # If the last p bytes of the data are all equal to p, return that the padding is valid and indicate the number of padding bytes

    return {"valid": False, "reason": "suffix does not match PKCS#7"}


def x923_chk(data: bytes, block_size: int = BLOCK_SIZE) -> Dict[str, Any]:

    if not data or len(data) % block_size != 0:

        return {"valid": False, "reason": "length is not a multiple of block size"}

    p = data[-1]

    if not 1 <= p <= block_size:

        return {"valid": False, "reason": "last byte outside padding range"}

    if data[-p:-1] == b"\x00" * (p - 1):

        return {"valid": True, "padding_bytes": p} # If the last p-1 bytes of the data (excluding the last byte) are all zero, return that the padding is valid and indicate the number of padding bytes

    return {"valid": False, "reason": "suffix does not match ANSI X.923"}


def iso7816_chk(data: bytes, block_size: int = BLOCK_SIZE) -> Dict[str, Any]:

    if not data or len(data) % block_size != 0:

        return {"valid": False, "reason": "length is not a multiple of block size"}

    last = data[-block_size:]
    pos = last.rfind(b"\x80") # Find the last occurrence of the 0x80 byte in the last block of data

    if pos < 0:

        return {"valid": False, "reason": "0x80 marker not found in final block"}

    suffix = last[pos:]

    if suffix[0] == 0x80 and suffix[1:] == b"\x00" * (len(suffix) - 1):

        return {"valid": True, "padding_bytes": len(suffix)} # If the suffix starts with 0x80 and is followed by zero or more 0x00 bytes, return that the padding is valid and indicate the number of padding bytes

    return {"valid": False, "reason": "invalid ISO/IEC 7816-4 suffix"}


def zero_chk(data: bytes, block_size: int = BLOCK_SIZE) -> Dict[str, Any]:

    if not data:

        return {"valid": False, "reason": "empty data"}

    count = 0

    for b in reversed(data):

        if b != 0:

            break

        count += 1

    if count == 0:

        return {"valid": False, "reason": "no trailing zero bytes"} # If there are no trailing zero bytes in the data, return that the padding is invalid and provide a reason

    return {

        "valid": True,
        "padding_bytes": count,
        "warning": "zero padding is inherently ambiguous; trailing zeros may be part of the original data",
        "block_aligned": len(data) % block_size == 0,

    }


def detect_pad(data: bytes, block_size: int = BLOCK_SIZE, assume_plaintext: bool = False) -> Dict[str, Any]:

    if not assume_plaintext:

        return { # Ciphertext padding checks can't be trusted: a random suffix can coincidentally look like valid padding

            "status": "not_reliable_on_ciphertext",

            "raw_suffix_checks": {

                "PKCS#7_like": pkcs7_chk(data, block_size),
                "ANSI_X923_like": x923_chk(data, block_size),
                "ISO_7816_4_like": iso7816_chk(data, block_size),
                "Zero_like": zero_chk(data, block_size),

            },

            "warning": "A coincidental pattern in a ciphertext can occur by chance.",
        }

    return { # When the caller confirms this is plaintext, the padding checks are meaningful and reported directly

        "status": "plaintext_checked",
        "PKCS#7": pkcs7_chk(data, block_size),
        "ANSI X.923": x923_chk(data, block_size),
        "ISO/IEC 7816-4": iso7816_chk(data, block_size),
        "Zero padding": zero_chk(data, block_size),

    }


def block_aligm(data: bytes, block_size: int = BLOCK_SIZE) -> Dict[str, Any]:

    size = len(data)

    return {

        "size_bytes": size,
        "multiple_of_block_size": (size % block_size == 0),
        "remainder": size % block_size,        
        "possible_block_cipher_sizes": [

            8 if size % 8 == 0 else None, # Check if the size is a multiple of 8 bytes (common block size for DES and other ciphers)
            16 if size % 16 == 0 else None, # Check if the size is a multiple of 16 bytes (common block size for AES, Camellia and other ciphers)
            24 if size % 24 == 0 else None, # Check if the size is a multiple of 24 bytes (192-bit block size; not used by standard AES, but valid for the original Rijndael cipher with a non-standard block size)

        ],

    }


def byte_difference_analysis(a: bytes, b: bytes) -> Dict[str, Any]:

    n = min(len(a), len(b)) # Only compare the overlapping portion of both byte sequences (in case the files have different lengths)
    differences = []

    for i in range(n):

        if a[i] != b[i]:
            
            differences.append(
                {

                    "offset": i,
                    "offset_hex": f"0x{i:x}",
                    "a_hex": f"{a[i]:02x}",
                    "b_hex": f"{b[i]:02x}",
                    "xor_hex": f"{a[i] ^ b[i]:02x}",

                }

            )

    runs = []

    if differences:

        start = prev = differences[0]["offset"] # Initialize the current run of consecutive differing offsets with the first difference found

        for d in differences[1:]:

            pos = d["offset"]

            if pos == prev + 1:

                prev = pos

            else:

                runs.append({"start": start, "end": prev, "length": prev - start + 1}) # Append a dictionary representing the current run of consecutive differing byte positions to the list of runs, including the starting offset, ending offset, and length of the run
                start = prev = pos

        runs.append({"start": start, "end": prev, "length": prev - start + 1}) # Append the final run of consecutive differing byte positions to the list of runs after exiting the loop

    result = {

        "same_length": len(a) == len(b),
        "overlap_bytes": n,
        "different_positions": len(differences),
        "difference_ratio": len(differences) / n if n else 0.0,
        "difference_runs": runs,
        "differences": differences[:500],

    }

    if len(a) == len(b) and len(a) > 0:

        result["identical"] = (len(differences) == 0) # If the two byte sequences are of the same length and not empty, add a boolean field to the result indicating whether they are identical (i.e., have no differing positions)

    return result


def xor_comparison(a: bytes, b: bytes) -> Dict[str, Any]:

    n = min(len(a), len(b)) # Only compare the overlapping portion of both byte sequences
    
    if n == 0:

        return {"overlap_bytes": 0}

    xa = xor_bytes(a[:n], b[:n]) # XOR the two byte sequences: if both are ciphertexts produced with the same keystream/key, this cancels the keystream and leaves the XOR of the two plaintexts
    zeros = xa.count(0) # Count zero bytes in the XOR result, i.e. positions where the two inputs had identical bytes
    zero_run, zero_start = zeros_line(xa) # Find the longest run of identical bytes (zero XOR) between the two inputs
    printable = print_ratio(xa)

    bit_hamming = hamm_dist(a[:n], b[:n])
    total_bits = 8 * n

    return {

        "overlap_bytes": n,
        "xor_entropy": entropy(xa),
        "xor_print_ratio": printable,
        "xor_zero_bytes": zeros,
        "xor_zero_ratio": zeros / n,
        "zeros_line_bytes": zero_run,
        "zeros_line_offset": zero_start,
        "hamm_dist_bits": bit_hamming,
        "hamming_ratio": bit_hamming / total_bits if total_bits else 0.0,
        "xor_first_64_hex": xa[:64].hex(),

    }


def eqpos_byte(a: bytes, b: bytes) -> Dict[str, Any]:

    n = min(len(a), len(b))

    if n == 0:

        return {"overlap_bytes": 0}

    equal_positions = sum(x == y for x, y in zip(a[:n], b[:n]))

    return {"overlap_bytes": n, "equal_positions": equal_positions, "equal_ratio": equal_positions / n} # Return a dictionary containing the number of overlapping bytes, the count of equal byte positions, and the ratio of equal positions to the total overlap


def compos_block(a: bytes, b: bytes, block_size: int = BLOCK_SIZE) -> Dict[str, Any]:

    blocks_a = full_blocks(a, block_size)
    blocks_b = full_blocks(b, block_size)

    map_a = defaultdict(list)
    map_b = defaultdict(list)

    for i, block in enumerate(blocks_a):

        map_a[block].append(i) # Record every position in file A where this 16-byte block value occurs

    for i, block in enumerate(blocks_b):

        map_b[block].append(i) # Record every position in file B where this 16-byte block value occurs

    common = []

    for block in set(map_a) & set(map_b):

        common.append(
            
            {

                "block_hex": block.hex(),
                "positions_a": map_a[block],
                "positions_b": map_b[block],
                "occurrences_a": len(map_a[block]),
                "occurrences_b": len(map_b[block]),

            }

        )

    common.sort(key=lambda x: -(x["occurrences_a"] + x["occurrences_b"])) # Sort the common blocks by combined occurrence count (descending) so the most frequently shared blocks appear first

    same_positions = []

    for i in range(min(len(blocks_a), len(blocks_b))):

        if blocks_a[i] == blocks_b[i]:

            same_positions.append(i) # Append the index of the block to the list of same_positions if the blocks at that index in both sequences are equal

    return {

        "full_blocks_a": len(blocks_a),
        "full_blocks_b": len(blocks_b),
        "distinct_common_block_values": len(common),
        "same_block_at_same_position": len(same_positions),
        "same_block_positions": same_positions[:100],
        "common_blocks": common[:100],

    }


def classify(data: bytes, block_info: Dict[str, Any], text_info: Dict[str, Any]) -> Dict[str, Any]:

    n = len(data)
    ent = entropy(data)
    rep = block_info["repeat_rate"]
    ic = calculate_ic(data)
    printable = text_info["print_ratio"]
    norm_ent = entropy_norm(data) # Moved above its first use: this was previously assigned after being read below, which raised an UnboundLocalError on every call

    candidates = []
    warnings = []

    if n < 32:

        warnings.append("The sample is short; cryptographic conclusions will be limited.")

    if printable >= 0.90 and norm_ent < 0.85:

        candidates.append(("plaintext/text", 0.90)) # High printable ratio with moderate entropy is consistent with readable text

    elif printable >= 0.55 and norm_ent < 0.90:

        candidates.append(("structured or encoded data", 0.60)) # Some printable content but not enough/low enough entropy to be confident plaintext (e.g. base64, mixed binary/text)

    if n >= 256:

        high_entropy = ent >= 7.5 # With enough bytes, absolute entropy close to the 8 bits/byte maximum is a reliable signal

    else:

        high_entropy = norm_ent >= 0.95 # With few bytes, use the normalized entropy instead, since the maximum observable entropy is capped by the sample size

    if high_entropy and abs(ic - EXPECTED_RANDOM_IC) < 0.004:

        candidates.append(("high-entropy data consistent with encryption or compression", 0.75)) # High entropy plus an index of coincidence close to that of random data strengthens the case

    elif high_entropy:

        candidates.append(("high-entropy data; encryption/compression remains plausible", 0.60))

    if n < 256:

        warnings.append(

            f"The maximum observable entropy in this sample is log2({n}) = "
            f"{math.log2(n):.3f} bits/byte; therefore, the absolute entropy should not "
            f"be directly compared with 8 bits/byte."

        )

    if len(full_blocks(data)) >= 4 and rep > 0.0:

        score = min(0.99, 0.70 + rep * 0.8) # Higher repeat rate increases confidence, capped just below 1.0 since this is still only heuristic evidence
        candidates.append(("ECB-like deterministic block encryption / repeated plaintext blocks", score))
        warnings.append(

            "Repeated 16-byte blocks are a strong indicator of a deterministic mode "
            "(for exemple ECB), but don't prove AES-ECB by themselves."

        )

    if n >= 32 and n % 16 == 0 and ent >= 7.0 and rep == 0:

        candidates.append(("16-byte-block cipher mode (CBC/ECB/etc.) or another binary ciphertext", 0.65)) # Block-aligned size with high entropy and no repeated blocks fits a chained/randomized block mode

    if n >= 32 and rep == 0 and n % 16 != 0 and ent >= 7.2:

        candidates.append(("stream-like/CTR/GCM-style ciphertext (heuristic only)", 0.45)) # A size that isn't block-aligned suggests a stream cipher or a counter/GCM mode rather than a padded block mode

    if ent >= 6.5 and printable < 0.20 and rep < 0.05:

        candidates.append(("compressed or encrypted binary data", 0.55))

    if n in {128, 256, 384, 512}:

        warnings.append(

            "The size coincides with common lengths of RSA ciphertext (128/256/384/512 bytes), "
            "but the size alone does not identify RSA."

        )
 
    merged: Dict[str, float] = {}
    
    for name, score in candidates:

        merged[name] = max(merged.get(name, 0.0), score) # If the same candidate label was added more than once, keep only its highest score

    ranked = [

        {"candidate": name, "score": round(score, 3)}

        for name, score in sorted(merged.items(), key=lambda x: x[1], reverse=True) # Sort candidates by score, highest confidence first

    ]

    if not ranked:

        ranked = [{"candidate": "undetermined", "score": 0.0}] # No heuristic matched; report an explicit "undetermined" result instead of an empty list

    return {

        "candidates": ranked,
        "warnings": warnings,
        "definitive_algorithm_identification": False,
        "reason": (

            "Ciphertext isolated normally does not allow determining definitively "
            "AES/RSA/CBC/CTR/GCM/etc.; the classification should be treated as heuristic evidence."

        ),

    }


def analyze_file(filepath: str, assume_plaintext: bool = False) -> Dict[str, Any]:

    path = Path(filepath)

    with path.open("rb") as f:

        data = f.read()

    freq = byte_freq(data)
    blocks = reptd_blocks(data, BLOCK_SIZE)
    strs = ascii_str(data)
    magic = detect_magic(data)

    text_info = {

        "print_ratio": print_ratio(data),
        "utf8_print_ratio": utf8_ratio(data),
        "ascii_str_count": len(strs),
        "ascii_str_sample": strs[:50],
        "null_byte_ratio": (data.count(0) / len(data)) if data else 0.0,

    }

    raw_entropy = entropy(data)
    metrics = {

        "size_bytes": len(data),
        "entropy_bits_per_byte": raw_entropy,
        "maximum_observable_entropy_bits_per_byte": (

            math.log2(min(len(data), 256)) if len(data) > 1 else 0.0

        ),

        "entropy_norm": entropy_norm(data),
        "chi_sq": chi_sq(data),
        "calculate_ic": calculate_ic(data),
        "expected_random_ic": EXPECTED_RANDOM_IC,
        "serial_corr_lag1": serial_corr(data, lag=1),

    }

    classification = classify(data, blocks, text_info)

    return {

        "file": str(path),
        "metrics": metrics,
        "alignment": block_aligm(data, BLOCK_SIZE),
        "byte_frequency_top": [

            {"byte_decimal": b, "byte_hex": f"{b:02x}", "count": c}
            for b, c in freq[:20]

        ],

        "block_analysis": blocks,
        "repeated_4grams": reptd_ngrams(data, 4, 20),
        "repeated_8grams": reptd_ngrams(data, 8, 20),
        "text_analysis": text_info,
        "magic_numbers": magic,
        "padding_analysis": detect_pad(data, BLOCK_SIZE, assume_plaintext),
        "classification": classification,
        "first_bytes_hex": data[:64].hex(),
        "_data": data,

    }


def compare_files(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:

    reports = []

    for a, b in combinations(results, 2):

        data_a = a["_data"]
        data_b = b["_data"]

        differences = byte_difference_analysis(data_a, data_b)
        xor = xor_comparison(data_a, data_b)
        positional = eqpos_byte(data_a, data_b)
        common_blocks = compos_block(data_a, data_b, BLOCK_SIZE)

        flags = []

        if common_blocks["same_block_at_same_position"] > 0:

            flags.append("Existem blocos completos de 16 bytes iguais na mesma posição.")

        if differences["same_length"] and 0 < differences["difference_ratio"] <= 0.10:

            flags.append(

                "Few positions differ between the files; this is compatible with "
                "localized corruption/modification and warrants byte-by-byte comparison."

            )

        if differences["same_length"] and differences["difference_ratio"] >= 0.90:

            flags.append(

                "Almost all bytes differ; the files appear independent or "
                "have been subjected to a different cryptographic transformation."

            )

        if (xor.get("hamming_ratio", 0.5) < 0.35 and xor.get("overlap_bytes", 0) >= 16):
            
            flags.append(

                "Hamming distance between the ciphertexts is below the expected for "
                "two independent random sequences; investigate reuse of "
                "keystream/nonce or strongly related data."

            )

        if xor.get("zeros_line_bytes", 0) >= 4:

            flags.append(

                "XOR contains a sequence of zeros; if the ciphertexts use the same "
                "keystream/nonce, this may indicate identical bytes in the plaintext at the same positions."

            )

        if positional.get("equal_ratio", 0.0) >= 0.10:

            flags.append(

                "High percentage of identical bytes at the same positions; warrants investigation."

            )

        reports.append(

            {

                "file_a": a["file"],
                "file_b": b["file"],
                "size_a": len(data_a),
                "size_b": len(data_b),
                "byte_difference_analysis": differences,
                "positional_comparison": positional,
                "xor_comparison": xor,
                "common_16byte_blocks": common_blocks,
                "flags": flags,

            }

        )

    return reports


def histo(data: bytes, path: str) -> str:

    try:

        import matplotlib.pyplot as plt

    except ImportError as exc:

        raise RuntimeError("matplotlib is not installed; use 'pip install matplotlib' or don't use --histogram.") from exc

    freq = [0] * 256

    for b in data:

        freq[b] += 1

    output = Path(path).with_suffix(Path(path).suffix + "_byte_histogram.png")
    plt.figure(figsize=(14, 6))
    plt.bar(range(256), freq, width=1.0)
    plt.xlabel("Byte (0-255)")
    plt.ylabel("Frequency")
    plt.title(f"Byte frequency - {Path(path).name}")
    plt.xlim(-1, 256)
    plt.tight_layout()
    plt.savefig(output, dpi=150)
    plt.close()

    return str(output)


def print_report(result: Dict[str, Any], verbose: bool = False) -> None:

    print("\n" + "=" * 78)
    print(f"FILE: {result['file']}")
    print("=" * 78)

    m = result["metrics"]
    a = result["alignment"]
    b = result["block_analysis"]
    t = result["text_analysis"]

    print(f"Size:                         {m['size_bytes']} bytes")
    print(f"Entropy:                      {m['entropy_bits_per_byte']:.5f} bits/byte")
    print(f"Max observable entropy:       {m['maximum_observable_entropy_bits_per_byte']:.5f} bits/byte")
    print(f"Normalized entropy:           {m['entropy_norm']:.3%}")
    print(f"Chi-square vs uniform:       {m['chi_sq']:.3f}")
    print(f"Index of coincidence:        {m['calculate_ic']:.6f}")
    print(f"Expected random IC:          {m['expected_random_ic']:.6f}")
    print(f"Serial correlation (lag 1):  {m['serial_corr_lag1']:.6f}")
    print(f"Multiple of 16 bytes:        {a['multiple_of_block_size']}")
    print(f"Remainder mod 16:             {a['remainder']}")
    print("\n--- Text / file information ---")
    print(f"Printable ratio:             {t['print_ratio']:.3f}")
    print(f"UTF-8 printable ratio:       {t['utf8_print_ratio']:.3f}")
    print(f"Null-byte ratio:             {t['null_byte_ratio']:.3f}")
    print(f"ASCII strings found:         {t['ascii_str_count']}")

    if result["magic_numbers"]:

        for item in result["magic_numbers"][:20]:

            print(f"Magic number:                {item['description']} "f"at offset {item['offset']} (0x{item['offset']:x})")

    else:

        print("Magic numbers:               none detected")

    print("\n--- 16-byte block analysis ---")
    print(f"Full blocks:                 {b['full_blocks']}")
    print(f"Unique blocks:               {b['unique_blocks']}")
    print(f"Repeated block groups:       {b['repeated_groups']}")
    print(f"Repeated block instances:    {b['repeated_block_instances']}")
    print(f"Repeated block rate:         {b['repeat_rate']:.3%}")

    if b["details"]:

        print("Repeated blocks:")

        for item in b["details"][:10]:

            print(f"  {item['block_hex']} | count={item['count']} | positions={item['positions']}")

    print("\n--- Padding ---")
    pad = result["padding_analysis"]
    print(f"Status:                      {pad['status']}")
    print(f"Message:                     {pad['message']}" if "message" in pad else "")

    if pad["status"] == "plaintext_checked":

        for name, info in pad.items():

            if name == "status":

                continue

            print(f"{name}: {info}")

    print("\n--- Heuristic classification ---")

    for candidate in result["classification"]["candidates"]:

        print(f"{candidate['score']:.3f}  {candidate['candidate']}")

    for warning in result["classification"]["warnings"]:

        print(f"WARNING: {warning}")

    print("\nFirst 64 bytes (hex):")
    print(result["first_bytes_hex"])

    if verbose:

        print("\nTop byte frequencies:")

        for item in result["byte_frequency_top"]:

            print(f"  0x{item['byte_hex']} ({item['byte_decimal']:3d}) -> {item['count']}")

        if t["ascii_str_sample"]:

            print("\nASCII strings:")

            for s in t["ascii_str_sample"]:

                print(f"  0x{s['offset']:x} ({s['offset']}): {s['text']}")

        for n_key in ("repeated_4grams", "repeated_8grams"):
            
            print(f"\n{n_key}:")
            items = result[n_key]

            if not items:

                print("  none")

            else:

                for item in items[:10]:

                    print(f"  {item['hex']} | count={item['count']} | positions={item['positions']}")


def print_comparison(reports: List[Dict[str, Any]]) -> None:
    
    print("\n" + "=" * 78)
    print("PAIRWISE COMPARISON")
    print("=" * 78)

    for r in reports:

        print(f"\n{r['file_a']}  <->  {r['file_b']}")

        d = r["byte_difference_analysis"]
        p = r["positional_comparison"]
        x = r["xor_comparison"]
        c = r["common_16byte_blocks"]

        print(f"Different byte positions:   {d['different_positions']}/{d['overlap_bytes']} "f"({d['difference_ratio']:.3%})")

        if d["difference_runs"]:

            print(f"Difference runs:             {d['difference_runs'][:10]}")

        if d["differences"] and len(d["differences"]) <= 30:

            print("Byte differences:")

            for item in d["differences"]:

                print(

                    f"  offset {item['offset']:4d} (0x{item['offset']:02x}): "
                    f"{item['a_hex']} -> {item['b_hex']} "
                    f"(XOR {item['xor_hex']})"

                )

        print(

            f"Same bytes at same positions: "
            f"{p.get('equal_positions', 0)}/{p.get('overlap_bytes', 0)} "
            f"({p.get('equal_ratio', 0.0):.3%})"

        )

        print(f"XOR entropy:                 {x.get('xor_entropy', 0.0):.5f}")
        print(f"XOR zero ratio:              {x.get('xor_zero_ratio', 0.0):.3%}")
        print(f"Longest XOR zero run:        {x.get('zeros_line_bytes', 0)} bytes")
        print(f"Hamming ratio:               {x.get('hamming_ratio', 0.0):.3%}")
        print(f"Same 16-byte block positions: {c.get('same_block_at_same_position', 0)}")
        print(f"Common distinct 16-byte blocks: {c.get('distinct_common_block_values', 0)}")

        if c["common_blocks"]:
            print("Common 16-byte blocks:")

            for item in c["common_blocks"][:10]:

                print(f"  {item['block_hex']} | A={item['positions_a']} | B={item['positions_b']}")

        if r["flags"]:

            print("Flags:")

            for flag in r["flags"]:

                print(f"  - {flag}")

        else:

            print("Flags: none")


def main() -> None:

    parser = argparse.ArgumentParser(description="Heuristic analyzer for encrypted/binary files.")
    parser.add_argument("files", nargs="+", help="Files to analyze")
    parser.add_argument( "-C", "--Compare", action="store_true", help="Compare every pair of input files")
    parser.add_argument( "-V", "--Verbose", action="store_true", help="Show more detailed information")
    parser.add_argument("-P", "--Plaintext", action="store_true", help="Treat input as plaintext when checking padding")
    parser.add_argument("-J", "--Json", action="store_true", help="Output JSON instead of the text report")
    parser.add_argument("-H", "--Histogram", action="store_true", help="Generate a byte-frequency histogram PNG")

    args = parser.parse_args()

    results = []

    for file_path in args.files:

        if not os.path.isfile(file_path):

            print(f"ERROR: file not found: {file_path}", file=os.sys.stderr)

            continue

        try:

            result = analyze_file(file_path, assume_plaintext=args.Plaintext)
            results.append(result)

        except Exception as exc:

            print(f"ERROR analyzing {file_path}: {exc}", file=os.sys.stderr)

    if not results:

        raise SystemExit(1)

    comparisons = compare_files(results) if args.Compare and len(results) >= 2 else [] # Perform pairwise comparisons of the analyzed files if the --compare flag is set and there are at least two results

    if args.son:

        serializable = []

        for result in results:

            copy_result = dict(result)
            copy_result.pop("_data", None)
            serializable.append(copy_result)

        output = {"files": serializable, "comparisons": comparisons} # Create a dictionary containing the analyzed file results (with the raw data removed) and any comparison results
        print(json.dumps(output, indent=2, ensure_ascii=False))

        return

    for result in results:

        print_report(result, verbose=args.Verbose) # Print a detailed report for each analyzed file, including metrics, text analysis, block analysis, padding analysis, and classification

        if args.Histogram:

            print(f"Histogram: {histo(result['_data'], result['file'])}") # Generate and print the path to a byte-frequency histogram PNG for the analyzed file if the --histogram flag is set

    if comparisons:

        print_comparison(comparisons) # Print a detailed report for each pairwise comparison of the analyzed files, including byte differences, positional comparisons, XOR comparisons, common 16-byte blocks, and any flags indicating potential issues or observations


if __name__ == "__main__":
    main()