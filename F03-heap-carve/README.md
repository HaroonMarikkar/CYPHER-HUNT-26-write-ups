[F03 - Heap Carve CTF Write-up.md](https://github.com/user-attachments/files/34521876/F03.-.Heap.Carve.CTF.Write-up.md)
# F03 - Heap Carve: CTF Write-up

Nov 7, 2026 · @HaroonMarikkar

## Challenge overview

F03 - Heap Carve (Forensics, Medium, 200 points) asks the analyst to rebuild an implant's session structure from a memory heap captured while the implant was live on AEGIS-APP-01, recover its encrypted configuration, and derive the operator identifier.

| Item | Detail |
| --- | --- |
| Series | GHOST IN THE GRID, an eight-stage DFIR investigation |
| Category / difficulty | Forensics / Medium |
| Provided file | GRID\_F03.zip |
| Contents | AEGIS-APP-01.bin (4,096-byte heap dump), c2\_session\_struct\_reference.h (structure reference) |
| Objective | Reconstruct the structure, recover the configuration, derive the operator identifier |
| Flag format shown | `VULNHAT{SHA-256(:)[:32]}` (field names missing on the page, see Step 4) |

<img width="895" height="677" alt="Screenshot 2026-11-07 191542" src="https://github.com/user-attachments/assets/bd2ebd72-a63c-49f4-b514-c32997c2edb8" />

## Tools and approach

The analysis was static: a memory dump was read and decrypted, and nothing was executed. The chain was: find the structure, read the key and the pointer, decrypt the blob, then hash the right fields.

- **HxD** (hex editor) to read the structure fields at known offsets
- **CyberChef** to cut out the blob and decrypt it with RC4
- **c2\_session\_struct\_reference.h** as the layout reference for the C2Context structure and the config blob
- **Browser developer tools** to read the raw flag-format text on the challenge page

## Step 1: Finding the structure

The reference header describes a 512-byte `C2Context` structure from the Havoc C2 framework. It says to search the dump for the magic `GRID_CTX` and that in this capture the structure begins at offset `0x0000`. The header also states the offsets of the fields needed:

| Field | Offset | Size | Use |
| --- | --- | --- | --- |
| magic | 0x0000 | 16 bytes | `GRID_CTX`, marks the structure start |
| session\_key | 0x0110 | 16 bytes | RC4 key for the config blob |
| session\_iv | 0x0120 | 16 bytes | Listed in the header, but not used by RC4 here |
| config\_blob\_ptr | 0x01F0 | 4 bytes, little-endian | File offset of the encrypted config blob |

The dump was opened in HxD. Offset `0x00` reads `GRID_CTX`, which confirms the structure starts at the beginning of the file.

<img width="1910" height="990" alt="Screenshot 2026-11-07 192206" src="https://github.com/user-attachments/assets/58b9e8d6-63d2-4744-bfe2-262dafb6b2fc" />

## Step 2: Extracting the key and the blob pointer

Both values were read directly from the hex view.

| Value | Offset | Raw bytes | Result |
| --- | --- | --- | --- |
| RC4 session key | 0x110 | `9A 3F 7C 21 B4 E8 05 D6 44 1A F7 82 C9 3E 61 50` | 16-byte key |
| Config blob pointer | 0x1F0 | `00 02 00 00` | Little-endian `0x00000200`, which is 512 decimal |

The pointer says the encrypted blob starts at file offset `0x200`. The hex view shows high-entropy data beginning exactly there, and the blob is 512 bytes long according to the header.

The 16 bytes at `0x120` are listed as an IV, but they contain the ASCII text `2024-10-07T16:04:33Z`. RC4 takes only a key, so the IV was not used, and using it would have given garbage.

<img width="1917" height="1020" alt="Screenshot 2026-11-07 192333" src="https://github.com/user-attachments/assets/a8879622-c3c4-4a4d-8534-1d888073883d" />


## Step 3: Decrypting the config blob

The heap dump was loaded into CyberChef with a three-operation recipe:

1. **Drop bytes**: start 0, length 512, which removes the 512 bytes before the blob.
2. **Take bytes**: start 0, length 512, which keeps only the blob.
3. **RC4**: passphrase `9A 3F 7C 21 B4 E8 05 D6 44 1A F7 82 C9 3E 61 50` as Hex, input and output format Latin1.

The output begins with the magic `HCFG`, which confirms the key and offset are right. The header defines the layout of the decrypted blob:

| Field | Value recovered |
| --- | --- |
| Magic | `HCFG` |
| operator\_token (32 hex characters) | `7c4e9f2a1d8b035648f1ca23e6079db4` |
| build\_timestamp | `2024-08-15T14:33:21Z` |
| campaign\_id | `PHANTOM_GRID_v2` |

Each field ends with a null byte, which is not part of the value. The timestamp in the heap at `0x120` (`2024-10-07T16:04:33Z`) belongs to the session, not the config, so it is a different value from the build timestamp.

<img width="1916" height="923" alt="Screenshot 2026-11-07 192648" src="https://github.com/user-attachments/assets/dbd37dc4-a29b-4459-86ca-4ad8a64264b2" />


## Step 4: Deriving the flag

The challenge page shows the flag format as `VULNHAT{SHA-256(:)[:32]}`. Inspecting the page's HTML with the browser developer tools showed the same text in the source, so the two field names inside the parentheses are missing on the platform itself. The colon indicates two values joined by `:`. The operator identifier is derived from the operator token and the build timestamp, so the hashed string is:

```
7c4e9f2a1d8b035648f1ca23e6079db4:2024-08-15T14:33:21Z
```

The string has no spaces and no trailing null byte. Hashing it with SHA-256 and keeping the first 32 hex characters gives:

**Flag:** `VULNHAT{b38977e2bf9019229642617963e1dcac}`

The flag template was incomplete, so the choice of fields was made from the challenge text and the structure header rather than read from the template.
<img width="1917" height="911" alt="Screenshot 2026-11-07 193026" src="https://github.com/user-attachments/assets/6a4c122e-c065-4cca-b30e-4ea174fbc4e7" />
<img width="1917" height="926" alt="Screenshot 2026-11-07 193304" src="https://github.com/user-attachments/assets/9f508bec-9065-4337-b814-32c0fb11b4f4" />


## Findings and lessons learned

The heap dump shows how an implant keeps its secrets in memory: the session key sits in the same structure as the pointer to the data it protects, so a memory capture exposes both.

- **Indicator:** the campaign ID `PHANTOM_GRID_v2` links this heap to the implant from the earlier challenge (F01), where the same string appeared in the decoded `.gdat` configuration.
- **Detection:** the `GRID_CTX` magic at the start of the structure and the `HCFG` magic of the decrypted blob are both searchable markers for memory scanning.
- **Technique:** RC4 with a 16-byte key stored next to the ciphertext pointer gives no real protection against someone with a memory image.
- **Pitfalls:** using the IV field with RC4 produces garbage, and the session timestamp in the heap is not the build timestamp in the config.
- **Platform issue:** the flag format on the page was missing its field names, so the field choice was inferred and should be confirmed with the organisers.
