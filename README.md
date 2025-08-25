# 🔐 dupe-finder.py — NTLM Password Reuse Auditor for Legit Pentests

> ⚠️ **Legal use only.** This utility is intended for **authorized internal security assessments** and red-team exercises. Always ensure you have written permission from the system/data owner before use.

When a Windows **domain has been compromised (DA/DP/NTDS)**, one of the fastest, high-impact hygiene checks is a **password audit**: which accounts have **cracked passwords** and where those passwords are **reused across users**.  
**dupe-finder.py** automates exactly that. You pull credentials with `secretsdump.py`, crack NTLM hashes with Hashcat, and this tool **groups users by NTLM hash** and **shows cracked passwords**—surfacing **password reuse** patterns at a glance. 🚀

Example:
```
evolab\lopper
EVolab\troll
EVolab\fister
have the password and NTLM - 59fc0f884922b4ce376051134c71e22c:Qwerty123

EVolab\adm-sat
has the password and NTLM - e19ccf75ee54e06b06a5907af13cef42:P@ssw0rd
```

---
**Quick start (example):**
```bash
# 1) Dump from DC (example Impacket usage, adjust flags to your opsec)
secretsdump.py -just-dc -no-pass CORP/dauser@dc01.corp.local > DC_dump.txt

# 2) Crack hashes with Hashcat (model 1000 = NTLM) and then collect cracked pairs
hashcat -m 1000 ntlm_hashes.txt rockyou.txt --show > passwords_from_hashcat.txt

# 3) Cluster by NTLM & print only cracked groups (largest first)
python3 dupe-finder.py DC_dump.txt passwords_from_hashcat.txt -o reuse_report.txt
```

---

---

## ✨ What it does

- ✅ Accepts either **raw** Impacket `secretsdump.py` output **or** ready-made **pwdump** lines  
- ✅ Accepts **Hashcat `--show`** results (`NTLM:password` format)  
- ✅ **Groups users by identical NTLM** (password reuse clusters)  
- ✅ **Prints only cracked** groups (where a plaintext password is known)  
- ✅ **Sorts by cluster size** (largest reuse first)  
- ✅ Optional `-o` to save results to a file  
- ✅ Pure Python 3, **no external deps** 🐍

---

## 🧠 Why it’s useful (post-compromise triage)

1. **Secrets collection:** Extract DC credentials with Impacket `secretsdump.py`.  
2. **Cracking:** Run Hashcat on NTLMs, then collect cracked entries via `hashcat --show`.  
3. **Clustering:** Run **dupe-finder.py** to identify:
   - Which **users have cracked passwords**  
   - Where **the same password is reused** and **how many times** 🔁  
   - Priorities for **forced resets** and **policy fixes**

---

## 🛠️ Requirements

- Python **3.8+**  
- Files produced by:
  - **Impacket** `secretsdump.py` (or any tool that yields `user:RID:LM:NTLM:::` lines)  
  - **Hashcat** `--show` output in the form `NTLM:plaintext`

---

## 📦 Installation

It’s a single file. Drop `dupe-finder.py` into your toolkit repo:

```bash
chmod +x dupe-finder.py
```

---

## 🔍 Input formats

**SECRETS_DUMP** (raw or pwdump): lines like
```
user:RID:LM:NTLM:::
```

**CRACKED** (Hashcat `--show`): lines like
```
NTLM:plaintext_password
```

The tool auto-detects and **extracts pwdump lines** from a raw `secretsdump.py` log using a regex, or treats the file as pwdump if extraction yields nothing.

---

## ▶️ Usage

```bash
# Basic
python3 dupe-finder.py SECRETS_DUMP CRACKED

# Save to a file
python3 dupe-finder.py SECRETS_DUMP CRACKED -o result.txt
```

---

## 📄 Output (what you’ll see)

For each **cracked NTLM**, the tool prints **all users that share it**, then a summary line with the **NTLM and plaintext**.  
It’s sorted so that **larger clusters** (more reuse) appear **first**.  
> Note: The script’s summary line is printed in Russian by default; feel free to localize the strings.

**Illustrative example (English paraphrase):**
```
alice
bob
charlie
have password and NTLM - <ntlm_hash>:<plaintext>

dan
has password and NTLM - <ntlm_hash_2>:<plaintext_2>
```

If nothing matches (no cracked NTLMs present), it prints:
```
No matching entries with known passwords were found.
```

---

## 🧩 How it works (under the hood)

- Extracts `user:RID:LM:NTLM:::` via regex from raw logs **or** reads pwdump lines directly  
- Normalizes 32-hex NTLMs and builds a mapping **NTLM → [users...]**  
- Reads `hashcat --show` **NTLM:password** pairs into **NTLM → password**  
- Keeps only NTLMs that exist in **both** maps (i.e., cracked)  
- **Sorts** by cluster size (desc), NTLM (asc), prints users + `NTLM:password`

---

## 🔐 OpSec & Privacy Tips

- Treat outputs as **sensitive**; they contain **plaintext passwords**.  
- Store reports in **encrypted** containers and **limit distribution**.  
- Use results to **enforce resets**, **ban reused passwords**, and **tighten policy**.  
- Delete intermediate artifacts when mission-complete. 🧹

---

## ⚖️ Legal / Ethics

This tool is for **legitimate, authorized** security work only.  
You are responsible for ensuring **lawful use** and adherence to contractual scope.

---

## 🧭 Roadmap (ideas)

- CSV/JSON output modes  
- Min-cluster threshold (`--min-size`)  
- English output strings by default / i18n  
- Optional export of **uncracked** accounts for follow-up  
- Complexity/length heuristics for cracked passwords

---

## 🙌 Acknowledgements

- [Impacket / secretsdump.py] for credential extraction  
- [Hashcat] for cracking & `--show` output

---
