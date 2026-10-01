#!/usr/bin/env python3

import sys
import os
import difflib

def bytes_rd(path):

    with open(path, "r", encoding="utf-8") as f:

        file = f.read()

    tokens = file.replace("\r", " ").replace("\n", " ").split() # Split the file content into tokens based on whitespace

    bytes = []

    for tk in tokens:

        tk = tk.strip()

        if not tk:

            continue

        try:

            val = int(tk, 16) # Convert the token from hexadecimal string to integer

        except ValueError:

            raise ValueError(f"Invalid hexadecimal value: {tk}")

        if not 0 <= val <= 255:

            raise ValueError(f"Value out of byte range: {tk}")

        bytes.append(val)

    return bytes # Return the list of byte values

def bytes_wr(path, data):

    with open(path, "w", encoding="utf-8") as f:

        f.write(" ".join(f"{b:02x}" for b in data)) # Write the byte values to the file in hexadecimal format, separated by spaces
        f.write("\n")

def comparison(raw, encrypted):

    diffs = []

    size = min(len(raw), len(encrypted))

    for i in range(size):

        if raw[i] != encrypted[i]:

            diffs.append({"index": i, "position": i + 1, "raw": raw[i], "encrypted": encrypted[i]}) # Append a dictionary containing the index, position, raw byte, and encrypted byte to the diffs list

    return diffs

def detc_groups(diffs):

    n = len(diffs)
    parent = list(range(n))

    def find(x): # Find the root of the set that x belongs to, with path compression

        while parent[x] != x:

            parent[x] = parent[parent[x]]
            x = parent[x]

        return x

    def union(x, y): # Union the sets that x and y belong to

        rx, ry = find(x), find(y)

        if rx != ry:

            parent[rx] = ry

    for a in range(n):

        d1 = diffs[a]

        for b in range(a + 1, n):

            d2 = diffs[b]

            if d1["raw"] == d2["encrypted"] or d2["raw"] == d1["encrypted"]:

                union(a, b)

    grps = {}

    for i in range(n):

        r = find(i)
        grps.setdefault(r, []).append(i)

    swaps = []
    chains = []
    linked_idx = set()

    for i in grps.values():

        if len(i) < 2:

            continue

        if len(i) == 2:

            i, j = i
            d1, d2 = diffs[i], diffs[j]
            cond_1 = d1["raw"] == d2["encrypted"]
            cond_2 = d2["raw"] == d1["encrypted"]

            if cond_1 and cond_2:

                swaps.append({
                    "pos1": d1["position"],
                    "pos2": d2["position"],
                    "byte1": d1["raw"],
                    "byte2": d2["raw"]
                })

                linked_idx.add(d1["index"])
                linked_idx.add(d2["index"])

                continue

        ord = sorted((diffs[i] for i in i), key=lambda d: d["index"]) # Sort the differences in the group by their original index
        chains.append(ord)

        for i in i:

            linked_idx.add(diffs[i]["index"])

    return swaps, chains, linked_idx # Return the lists of swaps, chains, and the set of linked index

def changes(diffs, linked_idx):

    chang = []

    for d in diffs:

        if d["index"] in linked_idx:

            continue

        chang.append({"position": d["position"], "raw": d["raw"], "encrypted": d["encrypted"]})

    return chang # Return the list of changes that are not part of any swap or chain

def sizes(raw, encrypted):

    moves = []
    delt = []
    insert = []

    matcher = difflib.SequenceMatcher(None, raw, encrypted) # Create a SequenceMatcher object to find differences between the raw and encrypted byte sequences

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():

        if tag == "equal":

            continue

        if tag == "replace":

            raw_reg = raw[i1:i2]
            enc_reg = encrypted[j1:j2]
            raw_set = set()
            enc_set = set()

            for i, byte_r in enumerate(raw_reg):

                for j, byte_e in enumerate(enc_reg):

                    if i in raw_set:

                        continue # Skip if this raw byte has already been matched

                    if j in enc_set:

                        continue # Skip if this encrypted byte has already been matched

                    if byte_r == byte_e:

                        moves.append({"orig_pos": i1 + i + 1, "new_pos": j1 + j + 1, "byte": byte_r}) # Record the move of the byte from its original position to the new position
                        raw_set.add(i) # Add the index of the raw byte to the set of matched raw bytes
                        enc_set.add(j) # Add the index of the encrypted byte to the set of matched encrypted bytes

                        break

            for i, byte in enumerate(raw_reg):

                if i not in raw_set:

                    delt.append({"position": i1 + i + 1, "byte": byte}) # Record the deletion of the raw byte that was not matched

            for j, byte in enumerate(enc_reg):

                if j not in enc_set:

                    insert.append({"position": j1 + j + 1, "byte": byte}) # Record the insertion of the encrypted byte that was not matched

        elif tag == "delete":

            for i in range(i1, i2):

                delt.append({"position": i + 1, "byte": raw[i]}) # Record the deletion of the raw byte

        elif tag == "insert":

            for j in range(j1, j2):

                insert.append({"position": j + 1, "byte": encrypted[j]}) # Record the insertion of the encrypted byte

    return (moves, delt, insert) # Return the lists of moves, deletions, and insertions

def report(swaps, chains, chang, moves, delt, insert, path):

    with open(path, "w", encoding="utf-8") as f:

        if not (swaps or chains or chang or moves or delt or insert):

            f.write("No differences found.\n")

            return

        if swaps:

            f.write("=== Position changes (swap) ===\n")

            for s in swaps:

                f.write("Position {} and {}: bytes {:02x} and {:02x} swapped positions\n".format(s["pos1"], s["pos2"], s["byte1"], s["byte2"]))

            f.write("\n")

        if chains:

            f.write("=== Permutation chains (3+ positions) ===\n")

            for idx, chain in enumerate(chains, start=1):

                f.write(f"Chain {idx}:\n")

                for d in chain:

                    f.write("  Position {}: byte {:02x} -> {:02x}\n".format(d["position"], d["raw"], d["encrypted"]))

            f.write("\n")

        if chang:

            f.write("=== Modifications (value changes) ===\n")

            for m in chang:

                f.write("Position {}: byte {:02x} was changed to {:02x}\n".format(m["position"], m["raw"], m["encrypted"]))

            f.write("\n")

        if moves:

            f.write("=== moves (bytes moved) ===\n")

            for m in moves:

                f.write("Byte {:02x} moved from position {} to {}\n".format(m["byte"], m["orig_pos"], m["new_pos"]))

            f.write("\n")

        if delt:

            f.write("=== Deletions (bytes removed) ===\n")

            for e in delt:

                f.write("Position {}: byte {:02x} was deleted\n".format(e["position"], e["byte"]))

            f.write("\n")

        if insert:

            f.write("=== Insertions (bytes added) ===\n")

            for i in insert:

                f.write("Position {}: byte {:02x} was inserted\n".format(i["position"], i["byte"]))

            f.write("\n")

def cclear(*paths):

    for path in paths:

        if os.path.exists(path):

            try:

                os.remove(path)

                print(f"Old file removed: {path}")

            except OSError as erro:

                print(f"Warning: Could not remove {path}: {erro}")

def show_diffs(diffs):

    print()
    print("=" * 70)
    print("BRUTE DIFFERENCES FOUND")
    print("=" * 70)

    for d in diffs:

        print("Position {:4d}: {:02x} -> {:02x}".format(d["position"], d["raw"], d["encrypted"]))

    print("=" * 70)

def verify(raw, encrypted):

    print()
    print("=" * 70)
    print("FIRST BYTES OF THE FILES")
    print("=" * 70)

    qutd = min(10, len(raw), len(encrypted))

    print("raw :", " ".join(f"{b:02x}" for b in raw[:qutd]))
    print("encrypted:"," ".join(f"{b:02x}"for b in encrypted[:qutd]))
    print("=" * 70)

def main():

    if len(sys.argv) != 3:

        print("\nUso:")
        print("python comparar.py " "raw.dat encrypted.dat")

        sys.exit(1)

    raw_file = sys.argv[1]
    encrypted_file = sys.argv[2]

    try:

        raw = bytes_rd(raw_file)
        encrypted = bytes_rd(encrypted_file)

    except Exception as erro:

        print(f"\nErro ao ler arquivo: {erro}")

        sys.exit(1)

    print()
    print("=" * 70)
    print("COMPARISON OF THE FILES")
    print("=" * 70)
    print(f"raw  : {raw_file}")
    print(f"encrypted: {encrypted_file}")
    print(f"size raw  : {len(raw)} bytes")
    print(f"size encrypted: {len(encrypted)} bytes")

    verify(raw, encrypted)

    if len(raw) == len(encrypted):

        diffs = comparison(raw, encrypted)
        show_diffs(diffs)
        swaps, chains, linked_idx = detc_groups(diffs)
        chang = changes(diffs, linked_idx)

        moves = []
        delt = []
        insert = []

    else:

        diffs = []
        swaps = []
        chang = []

        (moves, delt, insert) = sizes(raw, encrypted)

    base = os.path.splitext(encrypted_file)[0]
    report_file = (base + "_report.txt")
    fixed_file = (base + "_corrected.dat")

    cclear(report_file, fixed_file)
    report(swaps, chains, chang, moves, delt, insert, report_file)
    bytes_wr(fixed_file, raw)

    print()
    print("=" * 70)
    print("REPORT OF THE COMPARISON")
    print("=" * 70)
    print(f"Swaps found       : {len(swaps)}")
    print(f"Chains found: {len(chains)}")
    print(f"Modifications found: {len(chang)}")
    print(f"Moves found  : {len(moves)}")
    print(f"Deletions found   : {len(delt)}")
    print(f"Insertions found   : {len(insert)}")
    print()
    print(f"Report: {report_file}")
    print(f"Fixed: {fixed_file}")
    print("=" * 70)

if __name__ == "__main__":
    main()