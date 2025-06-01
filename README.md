# 🧪 MalDoc: Static Analysis

This project focuses on **static analysis of malicious Office documents (MalDocs)**. It demonstrates techniques for identifying embedded malicious code, VBA macros, and Indicators of Compromise (IOCs) without executing the file.

## 📌 Objective

To perform a thorough static analysis of a malicious Microsoft Office document and extract useful threat intelligence including:

- Metadata
- Embedded macros
- Suspicious strings and URLs
- Indicators of compromise (IOCs)

## 🧰 Tools Used

- `oletools` – for inspecting OLE files and extracting macro code
- `oledump.py` – to parse OLE streams and identify malicious payloads
- `oleid.py` – for metadata analysis
- `strings`, `base64`, `xorsearch` – for detecting obfuscated content
- `VirusTotal` – to cross-check extracted hashes/URLs

## 🔍 Analysis Steps

1. **File Inspection & Metadata Extraction**  
   Using `oleid.py` and `file` commands to assess document structure and type.

2. **Macro Extraction**  
   Analyzing with `olevba` and `oledump.py` to extract VBA code and scripts.

3. **IOC Collection**  
   Identifying domains, IPs, suspicious functions, and dropped files.

4. **Obfuscation Analysis**  
   Decoding obfuscated strings and inspecting encoding methods like base64/XOR.

5. **Threat Intelligence**  
   Cross-checking IOCs on VirusTotal and OSINT platforms.

## 📂 Files Included

- `sample.doc` – Malicious Office document (redacted or hash only)
- `analysis_report.txt` – Full static analysis report
- `extracted_macros.vba` – Cleaned and deobfuscated VBA code
- `ioc_list.txt` – List of extracted IOCs
- `tools/` – Scripts or tools used during analysis

## 🛡️ Learning Outcomes

- Improved familiarity with malware analysis tools
- Ability to identify and decode obfuscation techniques
- IOC extraction for threat hunting or alert creation
- Understanding of how Office-based malware operates statically
