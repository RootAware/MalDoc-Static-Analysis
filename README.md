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

# MalDoc: Static Analysis
**Objectives**

This project focuses on static analysis of malicious Microsoft Office documents to identify embedded malware without running the files. You will learn how to extract and analyze macros, decode obfuscated code, and inspect document metadata to uncover indicators of compromise. These skills help safely detect threats and support cybersecurity investigations.

**Scenario**

A targeted phishing campaign delivers a Microsoft Office document with a malicious macro designed to compromise victims’ systems. Opening the document may trigger harmful scripts that download malware or execute unauthorized commands. To avoid accidental infection, analysts perform static analysis—dissecting the file’s contents without running it.

Your role as a cybersecurity analyst is to investigate a suspicious Office document by extracting embedded macros, decoding obfuscated code, and analyzing the document’s structure and metadata. This process reveals attacker tactics, techniques, and procedures (TTPs) embedded in the file.


**1. Navigating to the Directory**

In the first step we are navigating to the directory where the suspicous file is located



![Capture2](https://github.com/user-attachments/assets/40854976-2153-47e3-bc10-bcb58be7f44e)

**2. Determining File Format Using TrID**

In this step, we use TrID to accurately identify the true file type of the suspicious document based on its binary signatures, bypassing any misleading file extensions

Overall, this means the file is very likely a Word document but may contain some variations or embedded OLE2 objects (like macros or embedded data).

![Capture3](https://github.com/user-attachments/assets/5bf41b2d-4c96-446c-aa8a-bf2334388ea1)


**3. Detecting Malicious Indicators with**

In this step, we use oleid to inspect the document’s internal structure and detect indicators such as embedded macros, suspicious streams, and encryption that may suggest malicious behavior. 
![Capture5](https://github.com/user-attachments/assets/ba06794d-954d-4cd7-97c1-37ebea75a8cc)

The presence of VBA Macros: True confirms that the document contains embedded Visual Basic for Applications (VBA) macros. This strongly indicates that the file is capable of executing code when opened, which is a common method used by attackers to deliver malware. Such behavior warrants deeper static and dynamic analysis to understand its potential impact.

**4. Extracting Metadata with olemeta**

In this step, we use olemeta to extract metadata from the suspicious Microsoft Office document. Metadata includes information such as the author's name, last modified by, creation and modification dates, application used to create the document, and more. This data can provide valuable context during an investigation.

For example, unusual or missing metadata may suggest that the document was auto-generated by a tool rather than a legitimate Office application. Identifying a suspicious author name or modification date can also help correlate the document with known malicious activity or actor behavior.

![Capture4](https://github.com/user-attachments/assets/ca913835-0a9e-422c-9bef-9f29bdafc146)
![Capture5 2](https://github.com/user-attachments/assets/dc4254a5-a188-4bf0-bca8-95e4f652b5c2)

**5. Extracting File Timestamps with oletimes**
In this step, we use oletimes to extract detailed timestamp metadata from the OLE document, including when it was created, last saved, and most importantly, when macros or VBA code were last modified.

The Macro/VBA modification time is particularly significant because it can help determine when malicious code may have been injected into the document. If the macro modification time is recent or inconsistent with the document's creation or last saved time, it raises strong suspicion that the document has been tampered with for malicious purposes. This kind of timeline inconsistency is often a key indicator during malware investigations.
![Capture 6](https://github.com/user-attachments/assets/611987cf-cf3f-48ce-a9ee-331dc9bfcc4e)


**6. Visualizing OLE Structure with olemap**
In this step, we use olemap to generate a visual overview of the internal structure of the OLE file, highlighting embedded streams and storages. This tool provides a map-like representation that helps analysts identify the presence and layout of potentially malicious components such as macro streams (e.g., VBA, Macros, __SRP_, or dir entries).

By examining this visual structure, we can quickly spot anomalies—such as unexpected streams or hidden data structures—that often indicate tampering or embedded malicious code. olemap is especially helpful when trying to understand the hierarchy and relationships between various parts of the file without manually parsing each component.
![Capture 7](https://github.com/user-attachments/assets/82597dce-6bc6-4a46-be17-125fe27b2df0)


**7. Extracting and Analyzing Macros with olevba**
In this step, we use olevba to extract and analyze VBA macro code embedded within the suspicious document. olevba is a powerful tool that not only reveals the raw macro content but also scans for potentially malicious patterns such as suspicious keywords, auto-executing functions (like AutoOpen), obfuscated strings, and shell commands.

The output of olevba helps us assess whether the macros are benign, poorly coded, or intentionally malicious. For example, the presence of keywords like Shell, CreateObject, or encoded strings can indicate attempts to download payloads, execute PowerShell commands, or interact with the system — all common tactics used in macro-based malware.

This step is crucial in identifying the intent and capabilities of the document without executing the file.
![Capture8 i](https://github.com/user-attachments/assets/cfee4b50-5f12-4a0a-b41e-58fb0d4e3b7c)

![Capture 8 ii](https://github.com/user-attachments/assets/e584ef46-0dbc-441d-a72f-be5e922ae3ad)



**8.Inspecting OLE Streams with oledump.py**
In this step, we use oledump.py to analyze the internal structure of the document, listing all OLE streams and identifying those containing macros. Streams flagged with an "M" typically contain VBA code, which we can inspect for signs of malicious behavior.

Upon examining the macro streams, we discovered a command referencing powershell.exe. This is a critical finding — PowerShell is a powerful scripting tool often abused by attackers to download and execute malicious payloads, bypass security controls, or establish persistence.

The presence of powershell.exe suggests that the document was likely designed to execute a script automatically when opened, potentially giving an attacker remote access or allowing further exploitation of the system.

![Capture 9](https://github.com/user-attachments/assets/74ef0701-6a4b-4fb1-a900-d0f1e7ecc6b2)
![Capture 10](https://github.com/user-attachments/assets/169669e7-b264-4c2a-9287-1bf93001f80c)


**9. Analyzing Macro Behavior with Vipermonkey**
In this step, we use Vipermonkey, a specialized VBA macro emulator, to safely execute and analyze the behavior of the extracted VBA macros without running the actual malicious document. Vipermonkey helps us understand what actions the macro intends to perform by interpreting its code and revealing its final decoded commands and payloads.

This tool is especially useful for uncovering obfuscated or encoded scripts that are common in malicious macros. By emulating the macro execution, Vipermonkey exposes the true intent behind the code—such as launching PowerShell commands, downloading additional malware, or modifying system settings—without risking system compromise.

Using Vipermonkey allows analysts to safely dissect malicious macros and produce actionable intelligence for incident response and threat hunting.

![Capture11](https://github.com/user-attachments/assets/356cccdb-ad7c-4b06-a724-292df570fd5a)


**10. Decoding and Investigating Payload with CyberChef**
Using Vipermonkey, we emulated the VBA macro to extract the hidden base64-encoded payload embedded within the malicious document. This encoded data often contains additional scripts or files intended for later stages of the attack.

To analyze this payload, we decoded the base64 string using CyberChef, a powerful web-based tool for data transformation and analysis. Upon decoding, we discovered a URL pointing to a file named stage2.exe, indicating a second-stage malware payload designed to be downloaded and executed on the victim's machine.

This finding confirms a multi-stage attack where the initial document acts as a downloader, fetching more harmful software to establish deeper system compromise.

![Capture 12](https://github.com/user-attachments/assets/82e3b739-d266-4e40-a64f-52aaede5e7ff)

![Capture 14](https://github.com/user-attachments/assets/081ecb37-56f3-4f71-92b8-a45924b14fd4)







