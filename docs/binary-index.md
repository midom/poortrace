# Binary index format

`poortrace --build-index BINARY --index-output FILE` writes version 1.
`--binary-index FILE` reuses it. The file has no native Rust structures or
pointers. All integers use little-endian byte order. String offsets and file
offsets are 64 bits. An index can exceed 4 GiB even when its source ELF does not.

## Header

The header is 160 bytes. Its fields are `u64`, except for the eight-byte magic.

| Byte offset | Field |
| --- | --- |
| 0 | Magic: ASCII `PTRIDX01` |
| 8 | Format version: 1 |
| 16 | ELF machine: 62 for x86-64, 183 for AArch64 |
| 24 | Source `st_dev` |
| 32 | Source `st_ino` |
| 40 | Source size |
| 48 | Source modification time, seconds |
| 56 | Source modification time, nanoseconds |
| 64 | Source change time, seconds |
| 72 | Source change time, nanoseconds |
| 80 | String pool byte length |
| 88 | Symbol count |
| 96 | Symbol records file offset |
| 104 | Raw name order table file offset |
| 112 | Demangled name order table file offset |
| 120 | SDT metadata file offset |
| 128 | SDT metadata byte length |
| 136 | Total file length |
| 144 | FNV-1a 64-bit hash of header bytes 0 through 143 |
| 152 | Reserved, zero |

Times in seconds preserve the bits of signed `st_mtime` and `st_ctime`.
Source identity uses ordinary file stat. Process mapping identity checks remain
separate, including the Btrfs mount ID check.

## Tables

The string pool starts at byte 160. It contains UTF-8 raw and demangled names
without terminators. Repeated names share pool entries.

Symbol records follow the pool. Each record contains seven `u64` fields:

1. ELF virtual address.
2. Symbol size, or zero if unknown.
3. Executable ELF file offset.
4. Raw name file offset.
5. Raw name byte length.
6. Demangled name file offset.
7. Demangled name byte length.

Records are sorted by address, demangled name, raw name, and size. Only defined
text symbols inside file-backed executable load segments are included. Repeated
records from regular and dynamic symbol tables are removed. Distinct aliases and
ambiguous names remain available.

Each name order table contains `symbol_count` 32-bit record IDs, sorted by its
name bytes. Both tables follow the records without padding. The SDT metadata
follows the name tables. It is a bounded JSON object with `path`, `sites`, and
`site_error` fields. `sites` uses the existing poortrace SDT descriptor schema.
An unsupported SDT descriptor stores its diagnostic in `site_error`.

## Reading and writing

Readers check the version, architecture, source identity, exact table layout,
header hash, bounds, and UTF-8 of names used by a lookup. The header hash detects
header damage; it is not a content authentication hash. Name and address tables
support binary search. Globs with a literal prefix start with a name table search.

The source ELF is limited to 4 GiB. Each index is limited to 16 GiB, 16 million
records, and 16 MiB of SDT metadata. Writers use a new temporary file in the
output directory, flush it, check that the source did not change, then rename it
and sync the directory. Readers retain a read-only file mapping. Replace an
index atomically; do not modify or truncate a mapped index in place.
