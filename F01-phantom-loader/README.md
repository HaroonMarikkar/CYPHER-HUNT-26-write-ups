[F01 - Phantom Loader CTF Write-up.md](https://github.com/user-attachments/files/34521584/F01.-.Phantom.Loader.CTF.Write-up.md)
# F01 - Phantom Loader: CTF Write-up

Nov 7, 2026 · @HaroonMarikkar

## Challenge overview

F01 - Phantom Loader (Forensics, Medium) asks for the SHA-256 identifier of a hidden implant configuration, recovered from a suspicious executable found on AEGIS-APP-01.

| Item | Detail |
| --- | --- |
| Series | GHOST IN THE GRID, an eight-stage DFIR investigation (case GRID-AEGIS-2024-0847) |
| Category / difficulty | Forensics / Medium |
| Provided file | GRID\_F01.zip |
| Contents | svchost32.exe, phantom\_grid\_v2.yar, sandbox\_submission\_metadata.json |
| Objective | Recover the hidden implant configuration and derive its cryptographic identifier |
| Flag format | VULNHAT{SHA-256(\<implant configuration string>)\[:32\]} |

## Tools and approach

The sample was analysed statically only and was never executed. The approach was: verify the sample, find the XOR key, locate the encrypted section, decode it, then hash the result.

- **file, sha256sum, strings, YARA** for triage and identification
- **HxD** (hex editor) to inspect the DOS stub and the .gdat section
- **CyberChef** to apply the XOR decoding and SHA-256
- **Analyst-provided YARA rule and sandbox report** as the source of the encoding scheme

## Step 1: Triage

The archive was extracted and the two analyst files read first. The YARA rule comment states that the implant stores an XOR-obfuscated configuration string in a custom PE section named `.gdat`, and that the 4-byte XOR key sits in the DOS stub at a fixed offset from the MZ header. The sandbox report confirms a 1,536-byte PE32 with two sections (`.text`, `.gdat`) and no imports.

```bash
file svchost32.exe
sha256sum svchost32.exe
yara phantom_grid_v2.yar svchost32.exe
strings -a -n 6 svchost32.exe
```

- `file` reports a PE32 executable (GUI) for Intel 80386 with 2 sections.
- The SHA-256 is `ea3541c449ed182bb180bebb9cdad459e741f59bbe665f5a40e77edb57f7fc22`, which matches the hash in both the YARA rule and the sandbox report, so this is the correct sample.
- `strings` shows the DOS-mode message, the `.gdat` section name and a block of unreadable bytes, which is the encoded configuration.


## Step 2: Locating the key and the encoded section

The file was opened in a hex editor and the PE structure inspected.

| Item | Location | Finding |
| --- | --- | --- |
| DOS stub | offset 0x40 | Begins with `0E 1F BA 0E`, matching the YARA pattern `$dos_stub_pre` |
| XOR key | offset 0x44, 4 bytes | `4B 33 59 41` (ASCII `K3YA`), placed where a normal DOS stub would contain `00 B4 09 CD` |
| .text section | raw offset 0x200 | Code, 512 bytes |
| .gdat section | raw offset 0x400, 512 bytes | Encoded configuration followed by zero padding |

The key is not a normal part of the DOS stub, which confirms it was planted there by the implant author, as the analyst notes describe.

<img width="1917" height="991" alt="Screenshot 2026-11-07 185601" src="https://github.com/user-attachments/assets/97b5f359-9ed5-42f6-9a3d-b202435d976a" />

## Step 3: Decoding the configuration

The executable was loaded into CyberChef and a two-operation recipe applied.

1. **Drop bytes**: start 0, length 1024. This removes everything before the `.gdat` section at 0x400.
2. **XOR**: key `4B 33 59 41` (Hex), scheme Standard, null preserving off. The key repeats every 4 bytes.

The output is readable text:

```
PHANTOM_GRID_v2|grid-telemetry-cdn.com|3600|25|GRID-OP-2024
```

The text is followed by one `NUL` byte and then repeating `K3YA` characters. These are the zero padding of the section, which turn into the key when XORed. They are not part of the configuration.
<img width="1917" height="927" alt="Screenshot 2026-11-07 190144" src="https://github.com/user-attachments/assets/a8b482e7-3aad-437a-8373-45488ae22108" />
<img width="1917" height="925" alt="Screenshot 2026-11-07 190532" src="https://github.com/user-attachments/assets/7e6fbc13-d989-4daa-9e3f-61bfe4958390" />
<img width="1917" height="923" alt="Screenshot 2026-11-07 190719" src="https://github.com/user-attachments/assets/cdeff92d-9971-4b41-bcb4-fa03b5cdefdf" />

## Step 4: Deriving the flag

The flag is the first 32 hex characters of the SHA-256 of the configuration string, so the string must be hashed exactly, with no trailing `NUL` byte.

1. **Take bytes**: start 0, length 59. This keeps only the 59 characters of the string and drops the `NUL` and padding.
2. **SHA2**: size 256.
3. Keep the first 32 characters of the hash.

| Item | Value |
| --- | --- |
| Configuration string (59 bytes) | `PHANTOM_GRID_v2\|grid-telemetry-cdn.com\|3600\|25\|GRID-OP-2024` |
| SHA-256 (first 32 hex characters) | `0b5eb8d38cd487781c051f7a8037708c` |

**Flag:** `VULNHAT{0b5eb8d38cd487781c051f7a8037708c}`
<img width="1917" height="917" alt="Screenshot 2026-11-07 190802" src="https://github.com/user-attachments/assets/d20db809-a4cd-4fb2-bac4-5c961c3cf0ec" />

<img width="1917" height="915" alt="Screenshot 2026-11-07 191145" src="https://github.com/user-attachments/assets/f36b69ff-8afe-470c-aa5e-7123afac14fa" />

## Findings and lessons learned

The decoded configuration reads as implant beacon settings. The fields below are my interpretation from their format and the sandbox report, and are not confirmed by the challenge.

| Field | Value | Likely meaning |
| --- | --- | --- |
| Implant name | PHANTOM\_GRID\_v2 | Malware family identifier |
| Host | grid-telemetry-cdn.com | Command-and-control domain, consistent with the sandbox's outbound TCP 443 |
| 3600 | 3600 | Possibly the beacon interval in seconds |
| 25 | 25 | Possibly jitter, in percent |
| GRID-OP-2024 | GRID-OP-2024 | Operation or campaign tag |

- **Indicator:** the domain `grid-telemetry-cdn.com` and the SHA-256 `ea3541c4...7fc22` can be used for blocking and hunting.
- **Detection:** the .gdat section name and the odd bytes in the DOS stub are what the YARA rule keys on.
- **Technique:** single-key repeating XOR hides strings from a plain `strings` search, but the key is stored in the file itself, so static analysis recovers it.
- **Pitfall:** a stray trailing zero byte changes the SHA-256, so the string must be trimmed exactly.
