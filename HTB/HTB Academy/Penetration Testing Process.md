# Introduction to the Penetration Tester Path

* * *

This module is an introduction to the Penetration Tester [Job Role Path](https://academy.hackthebox.com/paths/jobrole) and a general introduction to Penetration Tests and each of the phases that we cover in-depth throughout the modules. We recommend starting the path with this module and referring to it periodically as you complete other modules to see how each topic area fits in the bigger picture of the penetration testing process. This module is also a great starting point for anyone new to HTB Academy or the industry.

This path is intended for aspiring penetration testers from all walks of life and experienced pentesters looking to upskill in a particular area, become more well-rounded or learn things from a different perspective. This path covers core concepts necessary to succeed at External Penetration Tests, Internal Penetration Tests (both network and Active Directory), and Web Application Security Assessments. Through each module, we dive deep into the specialized techniques, methodologies, and tools needed to succeed in a penetration testing role. The path takes students on a highly hands-on journey through all stages of a penetration test, from reconnaissance and enumeration to documentation and reporting, culminating with a simulated penetration test capstone module. Students who complete this path in its entirety will be armed with the practical skills and mindset necessary to perform professional security assessments against real-world networks at a basic to intermediate level. Each of our modules dives deep into the "why" behind the issues and tactics that we present and is not just a tutorial on running point-and-click tools. We weave in stories and scenarios from our real-world experience performing security assessments for clients in all verticals and local and federal government.

* * *

## HTB Academy Learning Philosophy

Our goal is to teach students how to see both sides of an issue and be able to find flaws that others may miss. We encourage each student to formulate their own repeatable and thorough methodology that can be applied to any assessment type, no matter the size of the environment or the client's industry. Learning in this way and working through hundreds of practical, hands-on examples, with each module culminating in one or more skills assessments, reinforces these concepts and builds "muscle memory" around the things we perform on every assessment. If we can perform the basics well, we have more time to dig deeper and provide extra value to our clients. For every vulnerability and misconfiguration we demonstrate, we discuss the underlying flaw, which helps us better understand how things work, why a particular tool may be failing, and provide more accurate remediation advice to our clients that can be uniquely tailored to their environment and risk appetite.

Our learning philosophy can be summed up as the following:

Our philosophy is "learn by doing," following a risk-based approach with a heavy emphasis on hands-on learning and legal & ethical use of our skills. We strive to teach our students the "why" behind a vulnerability and how to discover, exploit, remediate, detect, and prevent the flaw to create well-rounded professionals who can pass this all-encompassing knowledge & mindset on to their current/future clients or employers to assist them in securing their people, technologies and missions from modern cyber threats.

* * *

## Ethical and Legal Considerations

An essential part of the above philosophy is the terms `legal` and `ethical`. Penetration Testing is one of the few professions where you are, for a time (during the authorized testing period), allowed to perform actions against a company that would be against the law under other circumstances. Throughout the modules, in this path and others, we provide individual targets and mini networks (labs) to safely and legally practice the techniques we demonstrate. The HTB main platform contains 100s of boxes and multiple large, real-world lab networks to practice these skills. With the rise of gamification in our industry and access to more hands-on, realistic training material, we must remember that there is a line between legal and illegal actions that can easily be crossed if we try to practice our skills outside of these controlled environments. Performing passive OSINT and information gathering skills against a target to work on those skills is OK, provided we are only using public databases and search engines but not probing a company's external infrastructure. However, performing ANY scanning or activities that interact with `ANY` of an organization's systems without explicit written consent in the form of a Scope of Work (including a detailed scope of testing, contract, and rules of engagement) signed by both parties is against the law and could lead to legal and even criminal action being taken against us.

If you are ready to practice on real-world targets, you can get additional practice by participating in bug bounty programs hosted by organizations such as [HackerOne](https://hackerone.com/directory/programs) and [Bugcrowd](https://bugcrowd.com/programs). Through these bug bounty organizations, you can participate in web application testing activities against many different companies that offer a bug bounty program. Keep in mind that each of these programs has its own scope and rules of engagement, so familiarize yourself with them before starting any testing activities. Most of these programs do not allow automated scanning, making them a great way to practice your information gathering and manual web application testing skills.

Once you land your first penetration testing job, do your due diligence to ensure that the company is a legitimate organization performing assessments only after explicit coordination (and contract paperwork) is completed between the target company and client. While rare, some criminal organizations may pose as legitimate companies to recruit talent to assist with illegal actions. If you participate, even if your intentions are good, you can still be liable and get into legal and even criminal trouble. When working for any company, make sure that you have a copy of the signed scope of work/contract and a formal document listing the scope of testing (URLs, individual IP addresses, CIDR network ranges, wireless SSIDs, facilities for a physical assessment, or lists of email or phone numbers for social engineering engagements), also signed by the client. When in doubt, request additional approvals and documentation before beginning any testing. While performing testing, `stay within the scope of testing`. Do not stray from the scope if you notice other IP addresses or subdomains that look more interesting. Again, `if in doubt, reach out`. Perhaps the client forgot to add certain hosts to the scoping sheet. It does not hurt to reach out and ask if other hosts you notice should be included, but, again, make sure this is `in writing` and not just given on a phone call.

Our clients place great trust in us to come into their network and run tools that could potentially wreak havoc on their network and cause disruptions that could lead to downtime and loss of revenue. We must work with the guiding principle of `do no harm` and strive to perform all testing activities in a careful and measured way. Just because we can run a certain tool, should we? Could a particular exploit PoC potentially crash one or more servers? If in doubt about anything during an assessment, run it by your manager and the client and gain explicit consent `in writing` before proceeding.

To sum up, we are highly skilled, and great trust is placed in us. Do not abuse this trust, `always work ethically and within the bounds of the law`, and you will have a long and fruitful career and make great business and personal relationships along the way. Always strive to take the high road and do the right thing. `Document, document, document`. When in doubt, document and overcommunicate. Ensure that all of the "boring" compliance issues are taken care of first so you can rest easy and enjoy performing excellent comprehensive assessments for your clients as their trusted advisor.

* * *

## Penetration Tester Path Syllabus

The path simulates a penetration test against the company Inlanefreight broken down into various stages, covering the core concepts and tools that will make us stand out as penetration testers. The path culminates in an in-depth module on critical soft skills such as notetaking, organization, documentation, reporting, and client communication, and then a full-blown mock penetration test to practice all of our skills in one large, simulated company network. The modules that comprise the path are laid out as follows:

| **`Introduction`** |
| --- |
| 1\. [Penetration Testing Process](https://academy.hackthebox.com/module/details/90) |
| 2\. [Getting Started](https://academy.hackthebox.com/module/details/77) |

| **`Reconnaissance, Enumeration & Attack Planning`** |
| --- |
| 3\. [Network Enumeration with Nmap](https://academy.hackthebox.com/module/details/19) |
| 4\. [Footprinting](https://academy.hackthebox.com/module/details/112) |
| 5\. [Information Gathering - Web Edition](https://academy.hackthebox.com/module/details/144) |
| 6\. [Vulnerability Assessment](https://academy.hackthebox.com/module/details/108) |
| 7\. [File Transfers](https://academy.hackthebox.com/module/details/24) |
| 8\. [Shells & Payloads](https://academy.hackthebox.com/module/details/115) |
| 9\. [Using the Metasploit Framework](https://academy.hackthebox.com/module/details/39) |

| **`Exploitation & Lateral Movement`** |
| --- |
| 10\. [Password Attacks](https://academy.hackthebox.com/module/details/147) |
| 11\. [Attacking Common Services](https://academy.hackthebox.com/module/details/116) |
| 12\. [Pivoting, Tunneling, and Port Forwarding](https://academy.hackthebox.com/module/details/158) |
| 13\. [Active Directory Enumeration & Attacks](https://academy.hackthebox.com/module/details/143) |

| **`Web Exploitation`** |
| --- |
| 14\. [Using Web Proxies](https://academy.hackthebox.com/module/details/110) |
| 15\. [Attacking Web Applications with Ffuf](https://academy.hackthebox.com/module/details/54) |
| 16\. [Login Brute Forcing](https://academy.hackthebox.com/module/details/57) |
| 17\. [SQL Injection Fundamentals](https://academy.hackthebox.com/module/details/33) |
| 18\. [SQLMap Essentials](https://academy.hackthebox.com/module/details/58) |
| 19\. [Cross-Site Scripting (XSS)](https://academy.hackthebox.com/module/details/103) |
| 20\. [File Inclusion](https://academy.hackthebox.com/module/details/23) |
| 21\. [File Upload Attacks](https://academy.hackthebox.com/module/details/136) |
| 22\. [Command Injections](https://academy.hackthebox.com/module/details/109) |
| 23\. [Web Attacks](https://academy.hackthebox.com/module/details/134) |
| 24\. [Attacking Common Applications](https://academy.hackthebox.com/module/details/113) |

| **`Post-Exploitation`** |
| --- |
| 25\. [Linux Privilege Escalation](https://academy.hackthebox.com/module/details/51) |
| 26\. [Windows Privilege Escalation](https://academy.hackthebox.com/module/details/67) |

| **`Reporting & Capstone`** |
| --- |
| 27\. [Documentation & Reporting](https://academy.hackthebox.com/module/details/162) |
| 28\. [Attacking Enterprise Networks](https://academy.hackthebox.com/module/details/163) |

After completing this path, we recommend that students work towards a specialization, be it Active Directory, Web, or Reverse Engineering. We should slowly continue to build our skills in all areas to become as well-rounded as possible while striving for expert-level knowledge in at least one discipline. For those that may not yet feel confident enough to take on this Job Role Path, we recommend working through all of the modules in the `Information Security Foundations` [Skill Path](https://academy.hackthebox.com/paths), which will help build the prerequisite knowledge necessary to be successful in the Penetration Tester path. It is best to take the modules in the Penetration Tester Path in order, as the concepts build on each other. Throughout the path, we continually reiterate concepts and present things in different ways to give students more practice and scenarios to further their knowledge in a particular area. For example, Lateral Movement and Pillaging are vital skills to succeed as a penetration tester. We do not have separate modules for each of these phases because pillaging and lateral movement can be thought of as iterative processes that we will revisit many times during an assessment. Instead, we introduce tactics, techniques, and procedures for moving laterally and show a wide variety of scenarios where we can benefit from strong pillaging/post-exploitation skills.

The following section breaks down 36 different HTB Academy modules and how they fit into each phase of the penetration testing process.


# Academy Modules Layout

* * *

Hack The Box was initially created to give technical professionals a safe place to practice and develop hacking skills and was not ideally suited for beginners starting their IT/Security journeys. Hack The Box began as solely a competitive CTF platform with a mix of machines and challenges, each awarding varying amounts of points depending on the difficulty, to be solved from a "black box" approach, with no walkthrough, guidance, or even hints. As the platform evolved, we saw the need for more beginner-friendly content and a guided learning approach to supplement the competitive side of the platform. With that goal in mind, HTB Academy was born. We aim to provide beginner-friendly content while helping mid-level and advanced practitioners upskill in various areas. We also offer Starting Point on the main HTB platform, which aims to help users become more comfortable attacking individual targets using a guided approach and eventually transitioning to solving boxes independently and even playing the competitive boxes. Each person likely has their personal opinion of HTB, and it may not be for everyone. However, we would like to take the time to explain our point of view as experienced IT specialists from various fields, with many years of combined experience and different journeys from beginners to where we are today.

IT (Information Technology) is a major business function of most organizations that focuses on building, administering, and supporting the computer technology used by organizations to achieve their mission. IT is a term often used to encompass many specialized sub-disciplines like Cybersecurity, Information Security, Software Development, Database Administration, Network Administration, and more. To become "good" in this field requires considerable practice and effort. Cyber security can be a very challenging discipline because it requires the basic knowledge necessary for a typical IT specialist and a much deeper understanding of all areas (networking, Linux and Windows systems administration, scripting, databases, etc.). We don't need to be experts in every single area of IT. However, the more experience and knowledge we have, the easier our job as an IT security specialist or penetration tester will become. We cannot work confidently as penetration testers if we don't have a deep understanding of the technologies we are assessing. For example, a web developer focuses only on developing web applications and websites. This generally requires knowledge of HTML, JavaScript, CSS, SQL, and server-side programming languages, such as PHP. Even if the developer has over ten years of experience in his field, it only takes one mistake for the entire web server to be unusable or for data to be stolen. As an attacker, the trick is to find a way to identify and exploit these errors.

With this in mind, we have laid a foundation for our students because, in our experience, it is hard to know where to start. We have structured and built our learning material so that it may seem difficult `at first`, but with time you will realize that this is the easiest and most efficient way to teach such complex material efficiently. We want to make the learning process as easy and efficient as possible while emphasizing the core fundamentals and returning to them repeatedly. For example, many of our tasks are set up to get you to think in a certain way. We do this to help you develop the essential analytical skills that are imperative to be successful in a field that can have so much uncertainty. We want to help craft professionals who see things differently and question everything, which ultimately can help deliver more value to clients if you're able to find nuanced issues that other testers miss. We can't teach analytical skills and the ability to dig deeper and "question everything" in one single module or path. This can be compared to playing a musical instrument. We can't learn to play the guitar well without considerable practice. We can learn everything about a guitar, the history of guitars, the name of every component, etc., but if we pick one up without practice, we will not be able to produce music that is equivalent to our knowledge of guitars. This is the same in the field of penetration testing. We may know everything about the history of computers and be able to describe every component, but without deep hands-on experience, we won't be able to perform penetration testing at a high level.

The remainder of this section will explain how we have structured the modules in the way that we did to give you insight into our thought process and teaching philosophy. Our primary focus is creating engaging and empowering training resources that benefit individuals at `ALL` skill levels.

The module listing shown corresponds to the sequence we recommend for beginners or advanced users who are 'stuck' to follow, in order to improve in specific areas at each stage of the penetration testing process.

![Penetration testing process diagram: Pre-Engagement, Information Gathering, Vulnerability Assessment, Exploitation, Post-Exploitation, Lateral Movement, Proof-of-Concept, Post-Engagement.](8EOkACPLYufd.png)

* * *

## Pre-Engagement

The pre-engagement stage is where the main commitments, tasks, scope, limitations, and related agreements are documented in writing. During this stage, contractual documents are drawn up, and essential information is exchanged that is relevant for penetration testers and the client, depending on the type of assessment.

![Penetration testing process: Pre-Engagement, Information Gathering, Vulnerability Assessment, Exploitation, Post-Exploitation, Lateral Movement, Proof-of-Concept, Post-Engagement.](nCgO6y3bXY8L.png)

There is only one path we can take from here:

| **Path** | **Description** |
| --- | --- |
| `Information Gathering` | Next, we move towards the `Information Gathering` stage. Before any target systems can be examined and attacked, we must first identify them. It may well be that the customer will not give us any information about their network and components other than a domain name or just a listing of in-scope IP addresses/network ranges. Therefore, we need to get an overview of the target web application(s) or network before proceeding further. |

At this stage in the process, we should have a strong foundation that can be built through the following fundamental modules:

#### 1\. Learning Process

|  |  |
| --- | --- |
| [![Module logo for the Learning Process module.](W9I2XEWpWHkc.png)](https://academy.hackthebox.com/module/details/9) | To acquire this knowledge as quickly and as well as possible, we need to know how a human being's `Learning Process` works and how to avoid stumbling blocks during the process. In this module we learn the art of how our brain works and how we can use this knowledge to increase our learning efficiency dramatically. <br>Tier 0FundamentalGeneral12 Sections+10 3 hours |

In addition, we need fundamental knowledge about the world's most widely used operating systems. This includes `Linux` and `Windows` operating systems. Before we attack these systems, we first need to know how they work, so we can then learn how to best exploit them.

#### 2\. Linux Fundamentals

|  |  |
| --- | --- |
| [![Module logo for the Linux Fundamentals module.](ZTIOH5b1ISXS.png)](https://academy.hackthebox.com/module/details/18) | Linux is one of the most stable operating systems today, and ubiquitous in corporate networks. `Linux Fundamentals` is essential so we learn its structure and can take the appropriate steps to achieve our goals. <br>Tier 0FundamentalGeneral18 Sections+10 6 hours |

#### 3\. Windows Fundamentals

|  |  |
| --- | --- |
| [![Module logo for the Windows Fundamentals logo.](Et8JwdyIYVqq.png)](https://academy.hackthebox.com/module/details/49) | On the other hand, Windows is one of the more user-friendly operating systems that most companies find in their IT infrastructure. It is essential to understand `Windows Fundamentals` to be able to handle the operating system in the best possible way and achieve the desired results. <br>Tier 0FundamentalGeneral14 Sections+10 6 hours |

All connected systems communicate via different networks, routes, and protocols on the Internet or internal network. To understand how interconnected systems function and communicate, we must work through some theoretical components to understand key functionality and specific terms.

#### 4\. Introduction to Networking

|  |  |
| --- | --- |
| [![Module logo for the Introduction to Networking module.](WWwVewZAJzmv.png)](https://academy.hackthebox.com/module/details/34) | Most of the information world is interconnected, and understanding how hosts communicate and find each other on the Internet and within internal networks is another fundamental building block that we must master. Without deep understanding of `Networking`, we will not be effective in assessing interconnected systems. <br>Tier 0FundamentalGeneral12 Sections+10 3 hours |

Web applications represent a separate category. We are comfortable using a web browser and browsing websites. But what happens behind the scenes when we interact with a web application? Before attacking web applications, we must focus on how they function and the processes that occur on the backend when using a web application.

#### 5\. Introduction to Web Applications

|  |  |
| --- | --- |
| [![Module logo for the Introduction to Web Applications.](O4A5AvjrNGso.png)](https://academy.hackthebox.com/module/details/75) | Computer networking on the Internet is standardized over many layers and protocols. The most used type of applications are `Web Applications`. These are designed so that any user with a browser and internet connection can access the web pages on the Internet. <br>Tier 0FundamentalGeneral17 Sections+10 3 hours |

#### 6\. Web Requests

|  |  |
| --- | --- |
| [![Module logo for the Web Requests module.](1QUrfFp4ezA8.png)](https://academy.hackthebox.com/module/details/35) | The communication takes place through different types of `Web Requests`, which the web application processes with specific functions. We will cover various types of web requests and how web browsers use them in the background. Some web server misconfigurations may even grant us access to the system without having to even exploit a web application directly. <br>Tier 0FundamentalGeneral8 Sections+10 4 hours |

#### 7\. JavaScript Deobfuscation

|  |  |
| --- | --- |
| [![Module logo for the JavaScript Deobfuscation module.](4pxy4ZQwzFBS.png)](https://academy.hackthebox.com/module/details/41) | Most web applications nowadays are dynamic and include `JavaScript`, which we must also be familiar with to handle the dynamics of the web page correctly. JavaScript is a very popular programming language and is often obfuscated to make it difficult for attackers (and defenders) to understand the exact functionality of the code. <br>Tier 0FundamentalDefensive11 Sections+10 4 hours |

As we know, large IT networks need to be closely managed and secured. Most companies have a management structure, as managing hundreds or thousands of systems remotely or physically one by one would be unreasonable. For this reason, various technologies exist to facilitate and accelerate remote management of users, systems, and other resources.

#### 8\. Introduction to Active Directory

|  |  |
| --- | --- |
| [![Module logo for the Introduction to Active Directory module.](rR8fktk2lZUu.png)](https://academy.hackthebox.com/module/details/74) | Nowadays, most companies use a structured way of managing hundreds or thousands of computers and users. `Active Directory` is used to simplify and speed up management for administrators. <br>Tier 0FundamentalGeneral16 Sections+10 7 hours |

#### 9\. Getting Started

|  |  |
| --- | --- |
| [![Module logo for the Getting Started module.](J7bVCyPT3lJu.png)](https://academy.hackthebox.com/module/details/77) | What causes the most significant difficulty for most when starting out? The answer to this is much easier than most may imagine because all we have to do is `Get Started`. This module includes many tips and tricks for those just starting out, examples of what technologies we will see and what attack methods we will use, and a guided walkthrough of solving a vulnerable box, culminating in solving (for some of us) our first box without assistance. <br>Tier 0FundamentalOffensive23 Sections+10 8 hours |

* * *

## Information Gathering

Information gathering is an essential part of any assessment. Because information, the knowledge gained from it, the conclusions we draw, and the steps we take are based on the information available. This information must be obtained from somewhere, so it is critical to know how to retrieve it and best leverage it based on our assessment goals.

![Penetration testing process: Pre-Engagement, Information Gathering, Vulnerability Assessment, Exploitation, Post-Exploitation, Lateral Movement, Proof-of-Concept, Post-Engagement.](6460mpAT7S2g.png)

From this stage, the next part of our path is clear:

| **Path** | **Description** |
| --- | --- |
| `Vulnerability Assessment` | The next stop on our journey is `Vulnerability Assessment`, where we use the information found to identify potential weaknesses. We can use vulnerability scanners that will scan the target systems for known vulnerabilities and manual analysis where we try to look behind the scenes to discover where the potential vulnerabilities might lie. |

The information we gather in advance will influence the results of the `Exploitation` stage. From this, we can see if we have collected enough or dived deep enough. Time, patience, and personal commitment all play a significant role in information gathering. This is when many penetration testers tend to jump straight into exploiting a potential vulnerability. This often fails and can lead, among other things, to a significant loss of time. Before attempting to exploit anything, we should have completed thorough information gathering, keeping detailed notes along the way, focusing on things to hone in on once we get to the exploitation stage. Most assessments are time-based, so we don't want to waste time bouncing around, which could lead to us missing something critical. Organization and patience are vital while being as thorough as possible.

#### 10\. Network Enumeration with Nmap

|  |  |
| --- | --- |
| [![Module logo for the Network Enumeration with Nmap module.](vKU147GBaYdr.png)](https://academy.hackthebox.com/module/details/19) | Suppose we limit our scope to the corporate network infrastructure. In that case, we should know how to perform the `Network Enumeration with Nmap`, identify the potential targets, and bypass security measures like firewalls, intrusion prevention, and intrusion detection systems (IPS/IDS). <br>Tier IEasyOffensive12 Sections+10 7 hours |

#### 11\. Footprinting

|  |  |
| --- | --- |
| [![Module logo for the Footprinting module.](p7CEpRfh91Qb.png)](https://academy.hackthebox.com/module/details/112) | Once we have identified the potential targets, we need to know how the individual services of these hosts can be examined. It is essential to understand what these services are used for, how they can be misconfigured, and how we, as attackers, can exploit them for our purposes. Because every service that communicates via the network leaves its own `Footprint` that we have to discover, knowing these footprints will give us a more accurate picture of what steps we can take next as we head into the exploitation phase. <br>Tier IIMediumOffensive20 Sections+20 2 days |

#### 12\. Information Gathering - Web Edition

|  |  |
| --- | --- |
| [![Module logo for the Information Gathering - Web Edition module.](Un3D5Za71zsw.jpg)](https://academy.hackthebox.com/module/details/144) | In most cases, web servers and web applications contain a great deal of information that can be used against them. Since web is a vast technical area in its own right, it will be treated separately. A web server can run many web applications, and some of these applications may be only intended for the developers and administrators. Therefore, finding these is an essential part of our `Information Gathering - Web Edition`. We also want to discover as many web applications as possible and gather detailed information on their structure and function which will help inform our attacks.<br>Tier IIEasyOffensive10 Sections+20 7 hours |

Things can become quite complex when we want to find information about a target company on the Internet. After all, sifting through various sources and social media platforms is time-consuming and requires a great deal of attention and patience.

#### 13\. OSINT: Corporate Recon

|  |  |
| --- | --- |
| [![Module logo for the OSINT: Corporate Recon module.](fOd5FzQFL6Nz.png)](https://academy.hackthebox.com/module/details/28) | This type of research is called open-source intelligence (OSINT) and has many subcategories. In summary, this process involves gathering information from all publicly available sources. `OSINT: Corporate Recon`, gives us a clear and structured approach that will allow us to work through many different types of data and information sources. A simple example would be finding a private SSH key that allows us to log into the corporate network as an administrator. <br>Tier IVHardOffensive23 Sections+200 2 days |

* * *

## Vulnerability Assessment

The vulnerability assessment stage is divided into two areas. On the one hand, it is an approach to scan for known vulnerabilities using automated tools. On the other hand, it is analyzing for potential vulnerabilities through the information found. Many companies conduct regular vulnerability assessment audits to check their infrastructure for new known vulnerabilities and compare them with the latest entries in these tools' databases.

An analysis is more about `thinking outside the box`. We try to discover gaps and opportunities to trick the systems and applications to our advantage and gain unintended access or privileges. This requires creativity and a deep technical understanding. We must connect the various information points we obtain and understand its processes.

![Penetration testing process: Pre-Engagement, Information Gathering, Vulnerability Assessment, Exploitation, Post-Exploitation, Lateral Movement, Proof-of-Concept, Post-Engagement.](tiIrLwpGBJB2.png)

From this stage, there are four paths we can take, depending on how far we have come:

| **Path** | **Description** |
| --- | --- |
| `Exploitation` | The first we can jump into is the `Exploitation` stage. This happens when we do not yet have access to a system or application. Of course, this assumes that we have already identified at least one gap and prepared everything necessary to attempt to exploit it. |
| `Post-Exploitation` | The second way leads to the `Post-Exploitation` stage, where we escalate privileges on the target system. This assumes that we are already on the target system and can interact with it. |
| `Lateral Movement` | Our third option is the `Lateral Movement` stage, where we move from the already exploited system through the network and attack other systems. Again, this assumes that we are already on a target system and can interact with it. However, privilege escalation is not strictly necessary because interacting with the system already allows us to move further in the network under certain circumstances. Other times we will need to escalate privileges before moving laterally. Every assessment is different. |
| `Information Gathering` | The last option is returning to the `Information Gathering` stage when we do not have enough information on hand. Here we can dig deeper to find more information that will give us a more accurate view. |

The ability to analyze comes with time and experience. However, it also needs to be trained because proper analysis makes connections between different points and information. Connecting this information about the target network or target system and our experience will often allow us to recognize specific patterns. We can compare this to reading. Once we have read certain words often enough, we will know that word at some point and understand what it means just by looking at the letters.

#### 14\. Vulnerability Assessment

|  |  |
| --- | --- |
| [![Module logo for the Vulnerability Assessment module.](hXhOkyaT2zkC.png)](https://academy.hackthebox.com/module/details/108) | After summarizing the information, we can use automated tools to scan the defined targets to detect known vulnerabilities in the systems. First, however, we need to know the scoring systems and learn how to configure and use these tools efficiently. The `Vulnerability Assessment` performed by these tools can give us a better overview of the potential vulnerabilities and the configuration of the target system. From this, new paths and opportunities can be revealed to us to help us find another way into the system. <br>Tier 0EasyOffensive17 Sections+10 2 hours |

#### 15\. File Transfers

|  |  |
| --- | --- |
| [![Module logo for the File Transfers module.](3C5TU08ZBFYv.png)](https://academy.hackthebox.com/module/details/24) | Before we can efficiently exploit the potential vulnerabilities, we need to be familiar with techniques and methods to transfer the required data to the target systems. This is because manual adjustments are often necessary to circumvent specific restrictions. Knowing the ways and means to perform `File Transfers` is an essential component that we must master and there are many ways to transfer files both to and from Windows and Linux hosts. If we have found a potential gap and do not know how to transfer the corresponding data to the target system, it will lead us to a dead end.<br>Tier 0MediumOffensive8 Sections+10 3 hours |

#### 16\. Shells & Payloads

|  |  |
| --- | --- |
| [![Module logo for the Shells & Payloads module.](kdSL67JoJ0YA.png)](https://academy.hackthebox.com/module/details/115) | We also need to know what files we need to transfer to gain initial or further access to the systems. For this, it is necessary to know what `Shell & Payloads` are. With the help of the transmitted payloads, we get access to the command line of the target system. Many things have to be taken into consideration because these shells and payloads must be adapted to the environment and the targeted system. <br>Tier IMediumOffensive17 Sections+10 2 days |

#### 17\. Using the Metasploit-Framework

|  |  |
| --- | --- |
| [![Module logo for the Using the Metasploit-Framework module.](7W0qYV7c6E81.png)](https://academy.hackthebox.com/module/details/39) | In addition, there is a handy framework called `Metasploit-Framework` that covers many attacks, enumeration, and privilege escalation methods and makes it faster for us to configure and execute. It can help us speed up our processes and get into the target systems in a semi-automated way. However, before we can do this, we need to understand what this tool is capable of and its limitations. <br>Tier 0EasyOffensive15 Sections+10 5 hours |

* * *

## Exploitation

Exploitation is the attack performed against a system or application based on the potential vulnerability discovered during our information gathering and enumeration. We use the information from the `Information Gathering` stage, analyze it in the `Vulnerability Assessment` stage, and prepare the potential attacks. Often many companies and systems use the same applications but make different decisions about their configuration. This is because the same application can often be used for various purposes, and each organization will have different objectives.

![Penetration testing process: Pre-Engagement, Information Gathering, Vulnerability Assessment, Exploitation, Post-Exploitation, Lateral Movement, Proof-of-Concept, Post-Engagement.](VdWIK4IK3jYs.png)

From this stage, there are four paths we can take, depending on how far we have come:

| **Path** | **Description** |
| --- | --- |
| `Information Gathering` | Once we have initial access to the target system, regardless of how high our privileges are at that moment, we need to gather information about the local system. Whether we use this new information for privilege escalation, lateral movement, or data exfiltration does not matter. Therefore, before we can take any further steps, we need to find out what we are dealing with. This inevitably takes us to the vulnerability assessment stage, where we analyze and evaluate the information we find. |
| `Post-Exploitation` | `Post-exploitation` is mainly about escalating privileges if we have not yet attained the highest possible rights on the target host. As we know, more opportunities are open to us with higher privileges. This path actually includes the stages `Information Gathering`, `Vulnerability Assessment`, `Exploitation`, and `Lateral Movement` but from an internal perspective on the target system. The direct jump to post-exploitation is less frequent, but it does happen. Because through the exploitation stage, we may already have obtained the highest privileges, and from here on, we start again at `Information Gathering`. |
| `Lateral Movement` | From here, we can also skip directly over to `Lateral Movement`. This can come under different conditions. If we have achieved the highest privileges on a dual-homed system used to connect two networks, we can likely use this host to start enumerating hosts that were not previously available to us. |
| `Proof-of-Concept` | We can take the last path after gaining the highest privileges by exploiting an internal system. Of course, we do not necessarily have to have taken over all systems. However, if we have gained the Domain Admin privileges in an Active Directory environment, we can likely move freely across the entire network and perform any actions we can imagine. So we can create the `Proof-of-Concept` from our notes to detail and potentially automate the paths and activities and make them available to the technical department. |

This stage is so comprehensive that it has been divided into two distinct areas. The first category is general network protocols often used and present in almost every network. The actual exploitation of the potential and existing vulnerabilities is based on the adaptability and knowledge of the different network protocols we will be dealing with. In addition, we need to be able to create an overview of the existing network to understand its individual components' purposes. In most cases, web servers and applications contain a great deal of information that can be used against them. As stated previously, since web is a vast technical area in its own right, it will be treated separately. We are also interested in the remotely exposed services running on the target hosts, as these may have misconfigurations or known public vulnerabilities that we can leverage for initial access. Finally, existing users also play a significant role in the overall network.

#### 18\. Password Attacks

|  |  |
| --- | --- |
| [![Module logo for the Password Attacks module.](vFdyoKrf1tlr.png)](https://academy.hackthebox.com/module/details/147) | If potential usernames or passwords were found during our information gathering, we may be able to use them specifically to perform `Password Attacks` on the systems and applications and authenticate ourselves. This module covers various methods to obtain credentials both remotely and locally on Windows and Linux systems. <br>Tier IMediumOffensive18 Sections+10 8 hours |

#### 19\. Attacking Common Services

|  |  |
| --- | --- |
| [![Module logo for the Attacking Common services module.](XmimNZbPhgdV.png)](https://academy.hackthebox.com/module/details/116) | Due to the variety of attacks that can be carried out, attacks on specific network services and web applications differ. Therefore, these are separated into different modules, as many specific attacks can only be carried out against web applications. However, there are many essential network services that can almost always be found in any corporate network. Therefore, knowing how to `Attack Common Services` is another major concept that needs to be covered in detail. <br>Tier IIMediumOffensive19 Sections+20 8 hours |

#### 20\. Pivoting, Tunneling & Port Forwarding

|  |  |
| --- | --- |
| [![Module logo for the Pivoting, Tunneling & Port Forwarding module.](S6uJ09F3ecs9.png)](https://academy.hackthebox.com/module/details/158) | When `Pivoting`, the exploited system is used as a node between the external and internal networks or between different internal networks. This is used to communicate with the internal systems to which we can usually not establish a direct connection from the Internet or another host in the internal network. It does not matter whether these are hosted on-premise or in the cloud. Network access and restrictions can be configured to and from specific hosts, even in the cloud. `Tunnels` must also be created to be able to transfer data securely. `Port forwarding` is often used to forward a local port to the port of an exploited system. <br>Tier IIMediumOffensive18 Sections+20 2 days |

#### 21\. Active Directory Enumeration & Attacks

|  |  |
| --- | --- |
| [![Module logo for the Active Directory Enumeration & Attacks module.](paaCGU2JjM0t.jpg)](https://academy.hackthebox.com/module/details/143) | As we already know, most corporate networks are managed by administrators using Active Directory. Therefore, it is crucial to become familiar with this technology and how `Active Directory Enumeration & Attacks` can affect it. Its complexity can often lead to various vulnerabilities. Especially when administrators are careless or imprecise, vulnerabilities often arise that can lead to a complete domain takeover. <br>Tier IIMediumOffensive36 Sections+20 7 days |

#### Web Exploitation

Web exploitation is the second part of the exploitation stage. Many different technologies, improvements, features, and enhancements have been developed in this area over the last few years, and things are constantly evolving. As a result, many different components come into play when dealing with web applications. This includes many kinds of databases that require differing command syntax to interact with. Due to the diversity of web applications available to companies and their prevalence worldwide, we must deal with this area separately and focus intently on it. Web applications present a vast attack surface and are often the main accessible targets during external penetration testing engagements, so strong web enumeration and exploitation skills are paramount.

#### 22\. Using Web Proxies

|  |  |
| --- | --- |
| [![Module logo for the Using Web Proxies module.](pAPFzz2W0JIF.png)](https://academy.hackthebox.com/module/details/110) | Web servers and web applications work based on the HTTP/HTTPS protocol. Like other protocols, this protocol has a fixed structure for requests and responses. We will focus on `Using Web Proxies` to analyze and manipulate these requests. The way these requests and their HTTP headers can be manipulated plays a significant role in the results we can get from them. Even the absence of specific HTTP headers or too many allowed HTTP methods can be very dangerous for the webserver or web application quickly and easily. <br>Tier IIEasyOffensive15 Sections+20 8 hours |

#### 23\. Attacking Web Applications with Ffuf

|  |  |
| --- | --- |
| [![Module logo for the Attacking Web Applications with Ffuf module.](sDXrRdcVcGMl.png)](https://academy.hackthebox.com/module/details/54) | After learning which attack methods these web applications can be subject to, we can use many of these attack methods and start `Attacking Web Applications with Ffuf`. Since every web server and application works with many different parameters due to its link with the database, these parameters can be discovered manually and automatically. For this purpose, there are procedures and different possibilities that allow us to find these parameters to exploit further possible vulnerabilities. <br>Tier 0EasyOffensive13 Sections+10 5 hours |

#### 24\. Login Brute Forcing

|  |  |
| --- | --- |
| [![Module logo for the Login Brute Forcing module.](SGQ3hjJqBeHU.png)](https://academy.hackthebox.com/module/details/57) | Authentication mechanisms are a vital target. Using these, we can gain access to different user accounts with the help of specific vulnerabilities. One of the most effective ways of gaining access is through `Login Brute Forcing`. Almost all web applications that offer any kind of user-specific functions work with the help of some sort of authentication mechanisms. <br>Tier IIEasyOffensive11 Sections+20 6 hours |

#### 25\. SQL Injection Fundamentals

|  |  |
| --- | --- |
| [![Module logo for the SQL Injection Fundamentals module.](Pz5diECy44pu.png)](https://academy.hackthebox.com/module/details/33) | Whether it manages products or users, most every web application works with at least one database. This database is linked to the web application in some way and may open up another attack category called SQL Injection. With an understanding of `SQL Injection Fundamentals`, we can manipulate or exploit the database for our purposes by abusing functionality contained within the web application. <br>Tier 0MediumOffensive17 Sections+10 8 hours |

#### 26\. SQLMap Essentials

|  |  |
| --- | --- |
| [![Module logo for the SQLMap Essentials module.](1nNspFIzLSfM.png)](https://academy.hackthebox.com/module/details/58) | Many of the attacks against web application database are summarized in a tool called SQLMap and should therefore also be learned to speed up our process after manual inspection. `SQLMap Essentials` should be learned to apply the tool appropriately and adapt it to the web application. <br>Tier IIEasyOffensive11 Sections+20 8 hours |

#### 27\. Cross-Site Scripting (XSS)

|  |  |
| --- | --- |
| [![Module logo for the Cross-Site Scripting (XSS) module.](Uw10x1ljo4yo.png)](https://academy.hackthebox.com/module/details/103) | `Cross-site Scripting (XSS)` is another of the most common attack categories. These vulnerabilities can be leveraged to launch various attacks, such as phishing, session hijacking, and others. Among other things, we can also potentially take over web sessions from other users or even administrators. <br>Tier IIEasyOffensive10 Sections+20 6 hours |

#### 28\. File Inclusion

|  |  |
| --- | --- |
| [![Module logo for the File Inclusion module.](Gt4xozQisxkd.png)](https://academy.hackthebox.com/module/details/23) | Depending on the webserver configuration and the web application, some vulnerabilities allow us some type of `File Inclusion`. For example, we may be able to access files on the target system or use our own to execute code without being provided access by the developers or administrators. <br>Tier 0MediumOffensive11 Sections+10 8 hours |

#### 29\. Command Injections

|  |  |
| --- | --- |
| [![Module logo for the Command Injections module.](MQlazcLVFP5Q.png)](https://academy.hackthebox.com/module/details/109) | We do not always need to attack the database using SQL Injections or XSS. Often direct `Command Injections` can be used to execute system commands. Some command injections are easier to spot than others, which may require advanced knowledge of identifying and bypassing filters in place. <br>Tier IIMediumOffensive12 Sections+20 6 hours |

#### 30\. Web Attacks

|  |  |
| --- | --- |
| [![Module logo for the Web Attacks module.](GkFqp9omYjUF.png)](https://academy.hackthebox.com/module/details/134) | The other top 10 most critical vulnerabilities include HTTP Verb Tampering, IDOR, and XXE. These are more advanced `Web Attacks`, as they require some security filters and encodings to be bypassed. <br>Tier IIMediumOffensive18 Sections+20 2 days |

#### 31\. Attacking Common Applications

|  |  |
| --- | --- |
| [![Module logo for the Attacking Common Applications module.](e7CoBDAi1qTA.png)](https://academy.hackthebox.com/module/details/113) | Common web applications might be customized by administrators but are nevertheless used worldwide. Therefore, it is also essential to know how to `Attack Common Applications`. <br>Tier IIMediumOffensive22 Sections+20 2 days |

* * *

## Post-Exploitation

In most cases, when we exploit certain services for our purposes to gain access to the system, we usually do not obtain the highest possible privileges. Because services are typically configured in a certain way "isolated" to stop potential attackers, bypassing these restrictions is the next step we take in this stage. However, it is not always easy to escalate the privileges. After gaining in-depth knowledge about how these operating systems function, we must adapt our techniques to the particular operating system and carefully study how `Linux Privilege Escalation` and `Windows Privilege Escalation` work.

![Penetration testing process: Pre-Engagement, Information Gathering, Vulnerability Assessment, Exploitation, Post-Exploitation, Lateral Movement, Proof-of-Concept, Post-Engagement.](jzfC750v0u5x.png)

From this stage, there are four paths we can take, depending on how far we have come:

| **Path** | **Description** |
| --- | --- |
| `Information Gathering / Pillaging` | Before we can begin escalating privileges, we must first get an overview of the inner workings of the exploited system. After all, we do not know which users are on the system and what options are available to us up to this point. This step is also known as `Pillaging`. This path is not optional, as with the others, but essential. Again, entering the `Information Gathering` stage puts us in this perspective. This inevitably takes us to the vulnerability assessment stage, where we analyze and evaluate the information we find. |
| `Exploitation` | Suppose we have found sensitive information about the system and its' contents. In that case, we can use it to exploit local applications or services with higher privileges to execute commands with those privileges. |
| `Lateral Movement` | From here, we can also skip directly over to `Lateral Movement`. This can come under different conditions. If we have achieved the highest privileges on a dual-homed system used to connect two networks, we can likely use this host to start enumerating hosts that were not previously available to us. |
| `Proof-of-Concept` | We can take the last path after gaining the highest privileges by exploiting an internal system. Of course, we do not necessarily have to have taken over all systems. However, if we have gained the Domain Admin privileges in an Active Directory environment, we can likely move freely across the entire network and perform any actions we can imagine. So we can create the `Proof-of-Concept` from our notes to detail and potentially automate the paths and activities and make them available to the technical department. |

After we have gained access to a system, we must be able to take further steps from within the system. During a penetration test, customers often want to find out how far an attacker could go in their network. There are many different versions of operating systems. For example, we may run into Windows XP, Windows 7, 8, 10, 11, and Windows Server 2008, 2012, 2016, and 2019. There are also different distributions for Linux-based operating systems, such as Ubuntu, Debian, Parrot OS, Arch, Deepin, Redhat, Pop!\_OS, and many others. No matter which of these systems we get into, we have to find our way around it and understand the individual weak points that a system can have from within.

#### 32\. Linux Privilege Escalation

|  |  |
| --- | --- |
| [![Module logo for the Linux Privilege Escalation module.](MWof5BeIsGDp.png)](https://academy.hackthebox.com/module/details/51) | The vast majority of web servers that make up the World Wide Web run Linux. In addition, we will find many Linux-based servers hosting critical infrastructure services that individuals & organizations use to be more productive and efficient in their daily work. Because of this widespread use of Linux, we must understand the fundamentals. There are many ways to misconfigure Linux systems. Discovering these flaws and taking advantage of them to escalate privileges is covered in `Linux Privilege Escalation`. <br>Tier IIEasyOffensive28 Sections+20 8 hours |

#### 33\. Windows Privilege Escalation

|  |  |
| --- | --- |
| [![Module logo for the Windows Privilege Escalation module.](sOJty6rGxRVW.png)](https://academy.hackthebox.com/module/details/67) | Modern Windows systems, now have stronger security precautions (if an organization is diligent with patching), but administrator errors are possible in any environment. There are many different ways to find the misconfigurations in Windows-based systems, and we need them for `Windows Privilege Escalation`. <br>Tier IIMediumOffensive33 Sections+20 4 days |

* * *

## Lateral Movement

Lateral movement is one of the essential components for moving through a corporate network. We can use it to overlap with other internal hosts and further escalate our privileges within the current subnet or another part of the network. However, just like `Pillaging`, the `Lateral Movement` stage requires access to at least one of the systems in the corporate network. In the Exploitation stage, the privileges gained do not play a critical role in the first instance since we can also move through the network without administrator rights.

![Penetration testing process: Pre-Engagement, Information Gathering, Vulnerability Assessment, Exploitation, Post-Exploitation, Lateral Movement, Proof-of-Concept, Post-Engagement.](0f3BoccGTRPD.png)

There are three paths we can take from this stage:

| **Path** | **Description** |
| --- | --- |
| `Vulnerability Assessment` | If the penetration test is not finished yet, we can jump from here to the `Vulnerability Assessment` stage. Here, the information already obtained from pillaging is used and analyzed to assess where the network services or applications using an authentication mechanism that we may be able to exploit are running. |
| `Information Gathering / Pillaging` | After a successful lateral movement, we can jump into `Pillaging` once again. This is local information gathering on the target system that we accessed. |
| `Proof-of-Concept` | Once we have made the last possible lateral movement and completed our attack on the corporate network, we can summarize the information and steps we have collected and perhaps even automate certain sections that demonstrate vulnerability to the vulnerabilities we have found. |

Since both `Lateral Movement` and `Pillaging` require access to an already exploited system, these techniques and methods are covered in different modules, such as `Getting Started`, `Linux Privilege Escalation`, and `Windows Privilege Escalation`, and many others.

* * *

## Proof-of-Concept

The `Proof-Of-Concept` ( `POC`) is merely proof that a vulnerability found exists. As soon as the administrators receive our report, they will try to confirm the vulnerabilities found by reproducing them. After all, no administrator will change business-critical processes without confirming the existence of a given vulnerability. A large network may have many interoperating systems and dependencies that must be checked after making a change, which can take a considerable amount of time and money. Just because a pentester found a given flaw, it doesn't mean that the organization can easily remediate it by just changing one system, as this could negatively affect the business. Administrators must carefully test fixes to ensure no other system is negatively impacted when a change is introduced. PoCs are sent along with the documentation as part of a high-quality penetration test, allowing administrators to use them to confirm the issues themselves.

![Penetration testing process: Pre-Engagement, Information Gathering, Vulnerability Assessment, Exploitation, Post-Exploitation, Lateral Movement, Proof-of-Concept, Post-Engagement.](3uQfMeRKzDG0.png)

From this stage, there is only one path we can take:

| **Path** | **Description** |
| --- | --- |
| `Post-Engagement` | At this point, we can only go to the post-engagement stage, where we optimize and improve the documentation and send it to the customer after an intensive review. |

When we already have all the information we have collected and have used the vulnerability to our advantage, it does not take much effort to automate the individual steps for this.

#### 34\. Introduction to Python 3

|  |  |
| --- | --- |
| [![Module logo for the Introduction to Python 3 module.](vZz78Ab8Xdv4.png)](https://academy.hackthebox.com/module/details/88) | Python is one of the easiest programming languages to learn, and it is also quite powerful. This makes it easy to automate many steps and, with the help of comments in our code, to understand exactly how the vulnerability is exploited step-by-step. Therefore, `Introduction to Python 3` will be sufficient for most aspects of automation once we understand the structure of this programming language. <br>Tier IEasyGeneral14 Sections+10 5 hours |

* * *

## Post-Engagement

The `Post-Engagement` stage also includes cleaning up the systems we exploit so that none of these systems can be exploited using our tools. For example, leaving a bind shell on a web server that does not require authentication and is easy to find will do the opposite of what we are trying to do. In this way, we endanger the network through our carelessness. Therefore, it is essential to remove all content that we have transferred to the systems during our penetration test so that the corporate network is left in the same state as before our penetration test. We also should note down any system changes, successful exploitation attempts, captured credentials, and uploaded files in the appendices of our report so our clients can cross-check this against any alerts they receive to prove that they were a result of our testing actions and not an actual attacker in the network.

In addition, we have to reconcile all our notes with the documentation we have written in the meantime to make sure we have not skipped any steps and can provide a comprehensive, well-formatted and neat report to our clients.

#### 35\. Documentation & Reporting

|  |  |
| --- | --- |
| [![Module logo for the Documentation & Reporting module.](Y8UUAmxYoBuL.png)](https://academy.hackthebox.com/module/details/162) | We need to understand proper `Documentation and Reporting`, how to stay organized and take detailed notes, and how to write effectively and deliver high quality client deliverables. Practice in this area will simplify preparation of our reports and save us considerable time. This module also helps us optimize our notetaking and organization, which we must adapt to our needs to work as efficiently as possible. <br>Tier IIEasyGeneral8 Sections+20 2 days |

#### 36\. Attacking Enterprise Networks

|  |  |
| --- | --- |
| [![Module logo for the Attacking Enterprise Networks module.](38YnCGmGBfvj.png)](https://academy.hackthebox.com/module/details/163) | It is essential to get and keep an overall view of all these stages, their contents, and possible challenges. `Attacking Enterprise Networks` can be a daunting task, and we can get lost in the diversity of our options and overlook some of the essentials. So instead, we need to familiarize ourselves with how to attack such large networks and what vulnerabilities may exist with a large number of systems in a network. <br>Tier IIMediumOffensive14 Sections+20 2 days |

Now that we've covered the general layout of Academy modules regarding the penetration testing process, we'll briefly discuss how exercises and questions are presented in HTB Academy.


# Academy Exercises & Questions

* * *

We have all had that one situation during tests, exams, and interviews where we were asked questions that could have several correct answers, but we could not come up with the correct answer. We may think we know the right answer. However, we did not know what the questioner wanted to hear at that moment in time.

At that time, our situation (getting the job, passing the exam) depended on the "right" answer. Our skills were being assessed based on our responses, and they may have even felt like trick questions and seemed unfair and frustrating. There is actual science that deals with what questions are and what types of questions exist, which is discussed in more detail in the [Learning Process](https://academy.hackthebox.com/module/details/9) module. The questions we may have been asked may have been ones that have no honest answer or may even distract us from the train of thought and cause us to stutter mentally.

* * *

## The Goal

However, at Hack The Box Academy, we do not judge you by your answers. We also do not want to confuse you or interrupt your thought processes. We do not get anything out of it because we create the material for you so you can learn in the best possible way and gain real experience in this field. Therefore, we have entirely different goals with our questions and exercises than others you may come across in your studies and career.

We want you to link your knowledge with practice and thus create chains of association. None of our questions or exercises stray from the topic taught. The labs and questions that are supposed to put you into scenarios related to our real-world experiences are ideally/directly related to the materials taught.

Some students may find the questions too rough or too imprecise. At first glance, that may seem to be the case. However, if we reconcile the material taught and experiment a little, we will begin to see and understand the context of the content. Once we have recognized these connections, we have already gained experience. All our tasks are always thoroughly thought through. We strive to match each question and skills assessment with the module difficulty level, assumed prerequisite knowledge, and accurately mapped to the presented content.

Some questions will seem unclear at first, but the reality is that we will often not know what to look for during actual penetration test engagements. We also will not know how many vulnerabilities there are to find. So we will be given a rough task:

- Find as many vulnerabilities as possible within the given time.

We want to prepare you for real-world situations and give you the confidence and experience to solve the given tasks. We want you to gain experience. It is impossible without difficulty or making mistakes in practice, which is normal. Some tasks will challenge you, which is okay and a good thing because you will learn the most from the difficult tasks. Every task is easy when you know the answer. But finding the way to the solution is the art.

* * *

## Asking for Help

Whether you do it or not is up to you and what you want to achieve. Because in our opinion, with many years together in this field, we know that this difficulty level is by far the best way to see the big picture and become highly skilled. If you get stuck or frustrated in your studies, reach out to others for assistance, there is a whole community out there willing to help, but you have to be willing to put in the work.

Instead of saying "I can't solve X" or "Tell me the answer to X," try approaching things differently. Before asking a question, list out what you already know and what things you have already tried. In doing this, you may find the answer is right in front of you. If you are still stuck, framing your question with this background information will show whoever is helping you that you are putting in an effort and not just looking to "check a box" and move on.

`Asking good questions is a difficult skill to master, but it's necessary for us in our studies and careers`.

When you have a boss, it's usually best to come to them with a partial solution and ask them to help validate your assumptions instead of just giving you the answer. This will show that you have done your due diligence, and they can count on you to tackle challenging problems that others may shy away from. This attitude will help you immensely throughout your career and is especially beneficial in an uncertain role like a penetration tester, where almost every day, we are faced with complex technical puzzles that we must solve under time constraints, sometimes for needy or unpleasant clients. Keep working hard, learn how to ask for help, and pay it forward to others who are going through what you have experienced and you will go far in this industry.

* * *

## Words of Wisdom

Our goal is to make you skilled penetration testers and IT security specialists. It is our passion to share our knowledge with you. We know precisely what you are going through and how it feels. We have all been through these situations.

Stay the course on the material, even if you have difficulty understanding certain things. We have become known for our materials and machines being too tricky for beginners. Of course, without some knowledge, this is true. Nevertheless, that does not stop you from learning the material independently.

Below are some words of insight from each member of the HTB Academy team:

Advice from Cry0l1t3:

`The difficulty is the dimension of your success that you must decide to step into.`

Advice from mrb3n:

`Every day is a school day. Try to learn at least one new thing every single day.`

Advice from Dimitris:

`Closely monitor the ever-evolving threat landscape and try to understand/emulate the techniques, tactics, and procedures of adversaries in the wild. This way you can provide your future clients/employers with realistic engagements.`

Advice from plaintext:

`Keep it simple. Sometimes challenges can be complex, but the answers might be right in front of you. If you have a hunch, follow it before trying something more advanced.`

Advice from pedant:

`Sophistication breeds excellence; excellence breeds sophistication.`

Advice from 21y4d:

`The difference between your skill level and the module exercises is the amount you should improve. As you complete the path and review earlier exercises, you'll see that you can easily complete them, indicating your skill level has increased.`

Advice from LTNB0B:

`If you truly want to accomplish what you set your mind to, remain persistent! Keep learning, and know that persistence pays off!`

Advice from TreyCraf7:

` Don't be afraid to ask questions. Getting a peer or mentor's perspective on a problem can help you get back on track. Sometimes it just takes another set of eyes.`

Advice from sentinal:

`Staying in your comfort zone is easy. Challenging your potential will keep you moving forward.`

We wish you all the best on your journey and know that we will be here to support you in Discord and will constantly strive to release materials to help you reach and exceed your goals. The HTB Discord community is an excellent resource if you get stuck, are looking for a study partner, want to share a cool achievement, or need someone to chat with. Definitely take advantage of it.

With that being said, let's discuss what a penetration test is and the various types of penetration tests we may be asked to perform.


# Penetration Testing Overview

* * *

IT is an integral part of nearly every company. The amount of critical and confidential data stored in IT systems is constantly growing, as is dependence on the uninterrupted functioning of the IT systems in use. Therefore, attacks against corporate networks, disruption of system availability, and other ways of causing significant damage to a company (such as ransomware attacks) are becoming increasingly common. Important company information obtained through security breaches and cyber-attacks may be sold to competitors, leaked on public forums, or used for other nefarious purposes. System failures are deliberately triggered because they are increasingly difficult to counteract.

A `Penetration Test` ( `Pentest`) is an organized, targeted, and authorized attack attempt to test IT infrastructure and its defenders to determine their susceptibility to IT security vulnerabilities. A pentest uses methods and techniques that real attackers use. As penetration testers, we apply various techniques and analyses to gauge the impact that a particular vulnerability or chain of vulnerabilities may have on the confidentiality, integrity, and availability of an organization's IT systems and data.

- `A pentest aims to uncover and identify ALL vulnerabilities in the systems under investigation and improve the security for the tested systems.`

Other assessments, such as a `red team assessment`, may be scenario-based and focus on only the vulnerabilities leveraged to reach a specific end goal (i.e., accessing the CEO's email inbox or obtaining a flag planted on a critical server).

#### Risk Management

In general, it is also a part of `risk management` for a company. The main goal of IT security risk management is to identify, evaluate, and mitigate any potential risks that could damage the confidentiality, integrity, and availability of an organization's information systems and data and reduce the overall risk to an acceptable level. This includes identifying potential threats, evaluating their risks, and taking the necessary steps to reduce or eliminate them. This is done by implementing the appropriate security controls and policies, including access control, encryption, and other security measures. By taking the time to properly manage the security risks of an organization's IT systems, it is possible to ensure that the data is kept safe and secure.

However, we cannot eliminate every risk. There's still the nature of the inherent risk of a security breach that is present even when the organization has taken all reasonable steps to manage the risk. Therefore, some risks will remain. Inherent risk is the level of risk that is present even when the appropriate security controls are in place. Companies can accept, transfer, avoid and mitigate risks in various ways. For example, they can purchase insurance to cover certain risks, such as natural disasters or accidents. By entering into a contract, they can also transfer their risks to another party, such as a third-party service provider. Additionally, they can implement preventive measures to reduce the likelihood of certain risks occurring, and if certain risks do occur, they can put in place processes to minimize their impact. Finally, they can use financial instruments, such as derivatives, to reduce the economic consequences of specific risks. All of these strategies can help companies effectively manage their risks.

During a pentest, we prepare detailed documentation on the steps taken and the results achieved. However, it is the client's responsibility or the operator of their systems under investigation to rectify the vulnerabilities found. Our role is as trusted advisors to report vulnerabilities, detailed reproduction steps, and provide appropriate remediation recommendations, but we do not go in and apply patches or make code changes, etc. It is important to note that a pentest is not monitoring the IT infrastructure or systems but a momentary snapshot of the security status. A statement to this regard should be reflected in our penetration test report deliverable.

#### Vulnerability Assessments

`Vulnerability analysis` is a generic term that can include vulnerability or security assessments and penetration tests. In contrast to a penetration test, vulnerability or security assessments are performed using purely automated tools. Systems are checked against known issues and security vulnerabilities by running scanning tools like [Nessus](https://www.tenable.com/products/nessus), [Qualys](https://www.qualys.com/apps/vulnerability-management/), [OpenVAS](https://www.openvas.org/), and similar. In most cases, these automated checks cannot adapt the attacks to the configurations of the target system. This is why manual testing conducted by an experienced human tester is essential.

On the other hand, a pentest is a mix of automated and manual testing/validation and is performed after extensive, in most cases, manual information gathering. It is individually tailored and adjusted to the system being tested. Planning, execution, and selection of the tools used are much more complex in a pentest. Both penetration tests and other security assessments may only be carried out after mutual agreement between the contracting company and the organization that employs the penetration tester. This is because individual tests and activities performed during the pentest could be treated as criminal offenses if the tester does not have explicit written authorization to attack the customer's systems. The organization commissioning the penetration test may only request testing against its' own assets. If they are using any third parties to host websites or other infrastructure, they need to gain explicit written approval from these entities in most cases. Companies like Amazon no longer require prior authorization for testing certain services per this [policy](https://aws.amazon.com/security/penetration-testing/), if a company is using AWS to host some or all of their infrastructure. This varies from provider to provider, so it is always best to confirm asset ownership with the client during the scoping phase and check to see if any third parties they use require a written request process before any testing is performed.

A successful pentest requires a considerable amount of organization and preparation. There must be a straightforward process model that we can follow and, at the same time, adapt to the needs of our clients, as every environment we encounter will be different and have its own nuances. In some cases, we may work with clients who have never experienced a pentest before, and we have to be able to explain this process in detail to make sure they have a clear understanding of our planned activities, and we help them scope the assessment accurately.

In principle, employees are not informed about the upcoming penetration tests. However, managers may decide to inform their employees about the tests. This is because employees have a right to know when they have no expectation of privacy.

Because we, as penetration testers, can find personal data, such as names, addresses, salaries, and much more. The best thing we can do to uphold the [Data Protection Act](https://www.gov.uk/data-protection) is to keep this information private. Another example would be that we get access to a database with credit card numbers, names, and CVV codes. Accordingly, we recommend that our customers improve and change the passwords as soon as possible and encrypt the data on the database.

* * *

## Testing Methods

An essential part of the process is the starting point from which we should perform our pentest. Each pentest can be performed from two different perspectives:

- `External` or `Internal`

#### External Penetration Test

Many pentests are performed from an external perspective or as an anonymous user on the Internet. Most customers want to ensure that they are as protected as possible against attacks on their external network perimeter. We can perform testing from our own host (hopefully using a VPN connection to avoid our ISP blocking us) or from a VPS. Some clients don't care about stealth, while others request that we proceed as quietly as possible, approaching the target systems in a way that avoids firewall bans, IDS/IPS detection, and alarm triggers. They may ask for a stealthy or "hybrid" approach where we gradually become "noisier" to test their detection capabilities. Ultimately our goal here is to access external-facing hosts, obtain sensitive data, or gain access to the internal network.

#### Internal Penetration Test

In contrast to an external pentest, an internal pentest is when we perform testing from within the corporate network. This stage may be executed after successfully penetrating the corporate network via the external pentest or starting from an assumed breach scenario. Internal pentests may also access isolated systems with no internet access whatsoever, which usually requires our physical presence at the client's facility.

* * *

## Types of Penetration Testing

No matter how we begin the pentest, the type of pentest plays an important role. This type determines how much information is made available to us. We can narrow down these types to the following:

| **Type** | **Information Provided** |
| --- | --- |
| `Blackbox` | `Minimal`. Only the essential information, such as IP addresses and domains, is provided. |
| `Greybox` | `Extended`. In this case, we are provided with additional information, such as specific URLs, hostnames, subnets, and similar. |
| `Whitebox` | `Maximum`. Here everything is disclosed to us. This gives us an internal view of the entire structure, which allows us to prepare an attack using internal information. We may be given detailed configurations, admin credentials, web application source code, etc. |
| `Red-Teaming` | May include physical testing and social engineering, among other things. Can be combined with any of the above types. |
| `Purple-Teaming` | It can be combined with any of the above types. However, it focuses on working closely with the defenders. |

The less information we are provided with, the longer and more complex the approach will take. For example, for a blackbox penetration test, we must first get an overview of which servers, hosts, and services are present in the infrastructure, especially if entire networks are tested. This type of recon can take a considerable amount of time, especially if the client has requested a more stealthy approach to testing.

* * *

## Types of Testing Environments

Apart from the test method and the type of test, another consideration is what is to be tested, which can be summarized in the following categories:

|  |  |  |  |  |
| --- | --- | --- | --- | --- |
| Network | Web App | Mobile | API | Thick Clients |
| IoT | Cloud | Source Code | Physical Security | Employees |
| Hosts | Server | Security Policies | Firewalls | IDS/IPS |

It is important to note that these categories can often be mixed. All listed test components may be included depending on the type of test to be performed. Now we'll shift gears and cover the Penetration Process in-depth to see how each phase is broken down and depends on the previous one.


# Laws and Regulations

* * *

Each country has specific laws which regulate computer-related activities, copyright protection, interception of electronic communications, use and disclosure of protected health information, and collection of personal information from children, respectively.

It is essential to follow these laws to protect individuals from `unauthorized access` and `exploitation of their data` and to ensure their privacy. We must be aware of these laws to ensure our research activities are compliant and do not violate any of the provisions of the law. Failure to comply with these laws can result in civil or criminal penalties, making it essential for individuals to familiarize themselves with the law and understand the potential implications of their activities. Furthermore, it is crucial to ensure that research activities adhere to these laws' requirements to protect individuals' privacy and guard against the potential misuse of their data. By following these laws and exercising caution when conducting research activities, security researchers can help ensure that individuals' data is kept secure and their rights are protected. Here is a summary of the related laws and regulations for a few countries and regions:

| **Categories** | **USA** | **Europe** | **UK** | **India** | **China** |
| --- | --- | --- | --- | --- | --- |
| Protecting critical information infrastructure and personal data | [Cybersecurity Information Sharing Act](https://www.cisa.gov/resources-tools/resources/cybersecurity-information-sharing-act-2015-procedures-and-guidance) ( `CISA`) | [General Data Protection Regulation](https://gdpr-info.eu/) ( `GDPR`) | [Data Protection Act 2018](https://www.legislation.gov.uk/ukpga/2018/12/contents/enacted) | [Information Technology Act 2000](https://www.indiacode.nic.in/bitstream/123456789/13116/1/it_act_2000_updated.pdf) | [Cyber Security Law](https://digichina.stanford.edu/work/translation-cybersecurity-law-of-the-peoples-republic-of-china-effective-june-1-2017/) |
| Criminalizing malicious computer usage and unauthorized access to computer systems | [Computer Fraud and Abuse Act](https://www.justice.gov/jm/jm-9-48000-computer-fraud) ( `CFAA`) | [Network and Information Systems Directive](https://www.enisa.europa.eu/topics/state-of-cybersecurity-in-the-eu/cybersecurity-policies/nis-directive-2) ( `NISD 2`) | [Computer Misuse Act 1990](https://www.legislation.gov.uk/ukpga/1990/18/contents) | [Information Technology Act 2000](https://www.indiacode.nic.in/bitstream/123456789/13116/1/it_act_2000_updated.pdf) | [National Security Law](https://www.chinalawtranslate.com/en/2015nsl/) |
| Prohibiting circumventing technological measures to protect copyrighted works | [Digital Millennium Copyright Act](https://www.congress.gov/bill/105th-congress/house-bill/2281) ( `DMCA`) | [Cybercrime Convention of the Council of Europe](https://www.europarl.europa.eu/cmsdata/179163/20090225ATT50418EN.pdf) |  |  | [Anti-Terrorism Law](https://web.archive.org/web/20240201044856/http://ni.china-embassy.gov.cn/esp/sgxw/202402/t20240201_11237595.htm) |
| Regulating the interception of electronic communications | [Electronic Communications Privacy Act](https://www.congress.gov/bill/99th-congress/house-bill/4952) ( `ECPA`) | [E-Privacy Directive 2002/58/EC](https://eur-lex.europa.eu/legal-content/EN/ALL/?uri=CELEX%3A32002L0058) | [Human Rights Act 1998](https://www.legislation.gov.uk/ukpga/1998/42/contents) ( `HRA`) | [Indian Evidence Act of 1872](https://web.archive.org/web/20230223081850/https://legislative.gov.in/sites/default/files/A1872-01.pdf) |  |
| Governing the use and disclosure of protected health information | [Health Insurance Portability and Accountability Act](https://aspe.hhs.gov/reports/health-insurance-portability-accountability-act-1996) ( `HIPAA`) |  | [Police and Justice Act 2006](https://www.legislation.gov.uk/ukpga/2006/48/contents) | [Indian Penal Code of 1860](https://web.archive.org/web/20230324123747/https://legislative.gov.in/sites/default/files/A1860-45.pdf) |  |
| Regulating the collection of personal information from children | [Children's Online Privacy Protection Act](https://www.ftc.gov/legal-library/browse/rules/childrens-online-privacy-protection-rule-coppa) ( `COPPA`) |  | [Investigatory Powers Act 2016](https://www.legislation.gov.uk/ukpga/2016/25/contents/enacted) ( `IPA`) |  |  |
| A framework for cooperation between countries in investigating and prosecuting cybercrime |  |  | [Regulation of Investigatory Powers Act 2000](https://www.legislation.gov.uk/ukpga/2000/23/contents) ( `RIPA`) |  |  |
| Outlining individuals' legal rights and protections regarding their personal data |  |  |  | [Personal Data Protection Bill 2019](https://www.congress.gov/bill/116th-congress/senate-bill/2889) | [Measures for the Security Assessment of Cross-border Transfer of Personal Information and Important Data](https://www.mayerbrown.com/en/perspectives-events/publications/2022/07/china-s-security-assessments-for-cross-border-data-transfers-effective-september-2022) |
| Outlining individuals' fundamental rights and freedoms |  |  |  |  | [State Council Regulation on the Protection of Critical Information Infrastructure Security](http://english.www.gov.cn/policies/latestreleases/202108/17/content_WS611b8062c6d0df57f98de907.html) |

* * *

## USA

The [Computer Fraud and Abuse Act](https://www.justice.gov/jm/jm-9-48000-computer-fraud) ( `CFAA`) is a federal law that makes it a criminal offense to access a computer without authorization. It applies to computer-related activities, including hacking, identity theft, and spreading malware. The CFAA has been the focus of much criticism and controversy, with some arguing that its provisions are too far-reaching and could be used to criminalize legitimate security research. In addition, critics have raised the concern that people can interpret the CFAA's broad definitions of computer-related activities in a manner that could lead to the prosecution of activities that were not intended to be criminal offenses. Furthermore, the CFAA has been criticized for needing more clarity regarding the meaning of specific terms, making it difficult for individuals to understand their rights and responsibilities under the law. For these reasons, it is crucial for individuals to familiarize themselves with the law and to understand the potential implications of their activities.

The [Digital Millennium Copyright Act](https://www.congress.gov/bill/105th-congress/house-bill/2281) ( `DMCA`) includes provisions prohibiting circumventing technological measures to protect copyrighted works. This can consist of digital locks, encryption, and authentication protocols, which safeguard software, firmware, and other types of digital content. Security researchers should know the DMCA provisions to ensure their research activities do not violate the law. It is important to remember that circumventing copyright protection measures, even for research or educational activities, can result in civil or criminal penalties. As such, researchers must exercise caution and due diligence to avoid inadvertently running afoul of the DMCA.

The [Electronic Communications Privacy Act](https://www.congress.gov/bill/99th-congress/house-bill/4952) ( `ECPA`) regulates the interception of electronic communications, including those sent over the Internet. This law makes it unlawful to intercept, access, monitor, or store communications without one or both parties consent. Furthermore, the ECPA prohibits using intercepted communications as evidence in a court of law. The ECPA also outlines the responsibilities of service providers, as they are not allowed to divulge the contents of communications to anyone except the sender and the receiver. Therefore, the ECPA protects the privacy of electronic communications and ensures that individuals are not subjected to illegal interception or use of their communications.

The [Health Insurance Portability and Accountability Act](https://aspe.hhs.gov/reports/health-insurance-portability-accountability-act-1996) ( `HIPAA`) governs the use and disclosure of protected health information and includes a set of rules for safeguarding personal health information stored electronically. Researchers should know these requirements and ensure their research activities adhere to HIPAA regulations. This includes taking measures such as encrypting data, keeping detailed data access, and sharing records. Furthermore, research must be conducted by institutional policies and procedures, and the appropriate governance body must approve any changes made. Researchers must also be mindful of the possibility of data breaches and take steps to ensure that any personal health information is kept secure. Failure to comply with HIPAA regulations can result in severe legal and financial penalties, so researchers must ensure that their research activities comply with HIPAA.

The [Children's Online Privacy Protection Act](https://www.ftc.gov/legal-library/browse/rules/childrens-online-privacy-protection-rule-coppa) ( `COPPA`) is an important piece of legislation regulating the collection of personal information from children under 13. We must be aware of the provisions of COPPA and take precautions to ensure that our research activities do not violate any of the requirements of the Act. To comply with COPPA, researchers must exercise caution and take special steps to ensure that they are not collecting, using, or disclosing any personal information from children under the age of 13. Failure to comply with COPPA could result in legal action and penalties, so security researchers must familiarize themselves with the Act and comply with its provisions.

* * *

## Europe

The [General Data Protection Regulation](https://gdpr-info.eu/) ( `GDPR`) regulates the handling of personal data, strengthens individuals' rights over personal data, and imposes penalties of up to 4% of global annual revenue or 20 million euros, whichever is higher for non-compliance. Security researchers should be aware of these provisions and ensure that their research does not run afoul of GDPR. It's important to note that GDPR applies to any company that processes the personal data of EU citizens, regardless of the company's location.

The [Network and Information Systems Directive](https://www.enisa.europa.eu/topics/cybersecurity-policy/nis-directive-new) ( `NISD`) requires operators of essential services and digital service providers to take appropriate security measures and report specific incidents. It's important to note that the NISD applies to various organizations and individuals, including those conducting penetration testing and security research.

The [Cybercrime Convention of the Council of Europe](https://www.europarl.europa.eu/cmsdata/179163/20090225ATT50418EN.pdf), the first international treaty on crimes committed via the Internet and other computer networks, provides a framework for cooperation between countries in investigating and prosecuting cybercrime.

The [E-Privacy Directive 2002/58/EC](https://eur-lex.europa.eu/legal-content/EN/ALL/?uri=CELEX%3A32002L0058) regulates the processing of personal data in the electronic communication sector. This directive applies to personal processing data in connection with the provision of publicly available electronic communications services in the EU.

* * *

## UK

The [Computer Misuse Act 1990](https://www.legislation.gov.uk/ukpga/1990/18/contents) was introduced to address malicious computer usage. It is a criminal offense to access a computer system without authorization, modify data without permission, or misuse computers to commit fraud or other unlawful activities. The Act also allows for confiscating computers and other devices used to commission a computer misuse offense and encourages reporting computer misuse incidents to law enforcement authorities. It also provides for the implementation of various measures to help prevent computer misuse, including establishing a special law enforcement team and implementing appropriate security measures.

The [Data Protection Act 2018](https://www.legislation.gov.uk/ukpga/2018/12/contents/enacted) is an important piece of legislation that provides individuals with certain legal rights and protections regarding their personal data. It details the rights of individuals, such as the right to access their data, the right to have their personal data rectified, and the right to object to the processing of their data. Furthermore, it outlines the obligations of those who process personal data, such as securely and transparently and providing individuals with clear and understandable information about how their data is being used. By considering the Act, security researchers can ensure that their research is conducted responsibly and lawfully.

The [Human Rights Act 1998](https://www.legislation.gov.uk/ukpga/1998/42/contents) ( `HRA`) is an important piece of legislation in the United Kingdom that outlines individuals' fundamental rights and freedoms. It incorporates the European Convention on Human Rights into UK law. It ensures that individuals have the right to fair and equal treatment in various areas, such as the right to a fair trial, the right to private and family life, and the right to freedom of expression. It also gives individuals the right to access judicial remedies in cases where their rights have been violated. The Act also gives individuals the right to challenge the legality of any law or administrative action that violates their fundamental rights and freedoms. The HRA is an essential piece of legislation that helps protect individuals from abuse of power and ensures their rights are respected.

The [Police and Justice Act 2006](https://www.legislation.gov.uk/ukpga/2006/48/contents) was an Act of Parliament passed in the United Kingdom, which aimed to provide a comprehensive framework for reforming the criminal justice system and policing. The Act established several new criminal offenses, including the violation of inciting religious hatred and measures to protect children from exploitation and vulnerable adults. It also provided for the creation of the Serious Organised Crime Agency and a National DNA Database. The Act also set out new measures to tackle anti-social behavior, including introducing Anti-Social Behaviour Orders. Furthermore, it included provisions to modernize the coroners' system and provide additional powers to the police to combat terrorism. In addition, the Act sought to improve the rights of victims of crime and to provide increased protection for victims of domestic violence.

[Investigatory Powers Act 2016](https://www.legislation.gov.uk/ukpga/2016/25/contents/enacted) ( `IPA`) regulates the use of investigatory powers by law enforcement and intelligence agencies, including hacking and other forms of digital surveillance. The IPA also requires Internet and other communications providers to retain certain data types for a specified period.

[Regulation of Investigatory Powers Act 2000](https://www.legislation.gov.uk/ukpga/2000/23/contents) ( `RIPA`) regulates public authorities' use of covert investigatory techniques, including hacking and other forms of digital surveillance.

* * *

## India

The [Information Technology Act 2000](https://www.indiacode.nic.in/bitstream/123456789/13116/1/it_act_2000_updated.pdf) provides for legal recognition of transactions using electronic data interchange and other means of electronic communication. It also criminalizes hacking and other unauthorized access to computer systems and imposes penalties for such actions.

The [Personal Data Protection Bill 2019](https://www.congress.gov/bill/116th-congress/senate-bill/2889) is a proposed legislation to protect individuals' personal data and impose penalties for non-compliance.

The [Indian Evidence Act of 1872](https://legislative.gov.in/sites/default/files/A1872-01.pdf) and the Indian Penal Code of 1860 contain provisions that may be invoked in cases of cybercrime, including hacking and unauthorized access to computer systems. Security researchers should be aware of these laws and ensure our research does not run afoul.

* * *

## China

The [Cyber Security Law](https://digichina.stanford.edu/work/translation-cybersecurity-law-of-the-peoples-republic-of-china-effective-june-1-2017/) establishes a legal framework for protecting critical information infrastructure and personal data and requires organizations to comply with certain security measures and report certain types of security incidents.

The [National Security Law](https://www.chinalawtranslate.com/en/2015nsl/) criminalizes activities that threaten national security, including hacking and other unauthorized access to computer systems.

The [Anti-Terrorism Law](http://ni.china-embassy.gov.cn/esp/sgxw/202402/t20240201_11237595.htm) criminalizes activities that support or promote terrorism, including hacking and other unauthorized access to computer systems.

The [Measures for the Security Assessment of Cross-border Transfer of Personal Information and Important Data](https://www.mayerbrown.com/en/perspectives-events/publications/2022/07/china-s-security-assessments-for-cross-border-data-transfers-effective-september-2022) regulates the cross-border transfer of personal information and important data and also requires organizations to conduct security assessments and obtain approval from relevant authorities before transferring such data.

The [State Council Regulation on the Protection of Critical Information Infrastructure Security](http://english.www.gov.cn/policies/latestreleases/202108/17/content_WS611b8062c6d0df57f98de907.html) regulates critical information infrastructure protection. Also, it requires organizations to take certain security measures and report certain types of security incidents.

* * *

## Precautionary Measures during Penetration Tests

We have prepared a list of precautions we highly recommend following during each penetration test to avoid violating most laws. In addition, we should also be aware that some countries have additional regulations that apply to specific cases, and we should either inform ourselves or ask our lawyer.

|  | **Precautionary Measure** |
| --- | --- |
| `☐` | Obtain written consent from the owner or authorized representative of the computer or network being tested |
| `☐` | Conduct the testing within the scope of the consent obtained only and respect any limitations specified |
| `☐` | Take measures to prevent causing damage to the systems or networks being tested |
| `☐` | Do not access, use or disclose personal data or any other information obtained during the testing without permission |
| `☐` | Do not intercept electronic communications without the consent of one of the parties to the communication |
| `☐` | Do not conduct testing on systems or networks that are covered by the Health Insurance Portability and Accountability Act (HIPAA) without proper authorization |


# Penetration Testing Process

* * *

In the social sciences, a process is considered a term for the directed sequence of events. In an operational and organizational context, processes are referred to more precisely as work, business, production, or value creation processes. Processes are another name for programs running in computer systems, which are usually parts of the system software.

It is also essential to distinguish between `deterministic` and `stochastic` processes. A deterministic process is a process in which each state is causally dependent on and determined by other previous states and events. A stochastic process is one in which one state follows from other states only with a certain probability. Here, only statistical conditions can be assumed. For us, several of the above definitions overlap. We use the definition of the penetration testing process from the social sciences to represent `a course of events connected` with `deterministic processes`. This is because all of our steps are based on the events and results we can discover or provoke.

`A penetration testing process is defined by successive steps and events performed by the penetration tester to find a path to the predefined objective.`

Processes describe a specific sequence of operations within a particular time frame that leads to the desired result. It is also essential to note that processes do not represent a fixed recipe and are not a step-by-step guide. Our penetration testing processes must therefore be coarse and flexible. After all, every client has a unique infrastructure, desires, and expectations.

* * *

## Penetration Testing Stages

The most effective way to represent and define these is through interdependent `stages`. We often find in our research that these processes are presented in the form of a circular process. If we look at this more closely and imagine that even a single component of the circular process does not apply, the entire process is disrupted. Strictly defined, the whole process fails. If we assume that we start this process from the beginning, but already with the newly acquired information, it is already a new process approach that does not undo the previous one.

The problem is that with these representations and approaches, there is often nothing to fall back on to extend our penetration testing process. As we have discussed, there is no step-by-step guide we can follow but `stages` that allow the individual steps and approaches to be flexibly varied and adapted to the results and information we receive. We can develop our own playbook for various things we try at different stages of a penetration test, but every environment is different, and thus, we need to adapt constantly.

![Penetration testing process: Pre-Engagement, Information Gathering, Vulnerability Assessment, Exploitation, Post-Exploitation, Lateral Movement, Proof-of-Concept, Post-Engagement.](JgZReaSevlyF.png)

We will go into each of these stages in more detail and cover the specifics of each in later sections and look at an `optional study plan` on how to proceed to learn the many Tactics, Techniques, and Procedures (TTPs), using a structure to show how each stage builds on the other and can also be iterative in nature. First, let's look at the broad components of the penetration testing process and discuss the individual modules and why they are so important.

This optional study plan is based on sets of modules for each stage that we recommend working through before moving on to the next stage. We will work through different phases in almost all of the modules, performing steps such as `Information Gathering`, `Lateral Movement`, and `Pillaging` repeatedly. The separation of the modules is designed to focus on the topic, which requires specific knowledge that should not be skipped. Gaps in any of this knowledge, even if we think we are familiar with it, can lead to misunderstandings or difficulties in the course of the study. Accordingly, the penetration testing process with its stages looks as follows:

#### Pre-Engagement

`Pre-engagement` is educating the client and adjusting the contract. All necessary tests and their components are strictly defined and contractually recorded. In a face-to-face meeting or conference call, many arrangements are made, such as:

- `Non-Disclosure Agreement`
- `Goals`
- `Scope`
- `Time Estimation`
- `Rules of Engagement`

#### Information Gathering

`Information gathering` describes how we obtain information about the necessary components in various ways. We search for information about the target company and the software and hardware in use to find potential security gaps that we may be able to leverage for a foothold.

#### Vulnerability Assessment

Once we get to the `Vulnerability Assessment` stage, we analyze the results from our `Information Gathering` stage, looking for known vulnerabilities in the systems, applications, and various versions of each to discover possible attack vectors. Vulnerability assessment is the evaluation of potential vulnerabilities, both manually and through automated means. This is used to determine the threat level and the susceptibility of a company's network infrastructure to cyber-attacks.

#### Exploitation

In the `Exploitation` stage, we use the results to test our attacks against the potential vectors and execute them against the target systems to gain initial access to those systems.

#### Post-Exploitation

At this stage of the penetration test, we already have access to the exploited machine and ensure that we still have access to it even if modifications and changes are made. During this phase, we may try to escalate our privileges to obtain the highest possible rights and hunt for sensitive data such as credentials or other data that the client is concerned with protecting (pillaging). Sometimes we perform post-exploitation to demonstrate to a client the impact of our access. Other times we perform post-exploitation as an input to the lateral movement process described next.

#### Lateral Movement

Lateral movement describes movement within the internal network of our target company to access additional hosts at the same or a higher privilege level. It is often an iterative process combined with post-exploitation activities until we reach our goal. For example, we gain a foothold on a web server, escalate privileges and find a password in the registry. We perform further enumeration and see that this password works to access a database server as a local admin user. From here, we can pillage sensitive data from the database and find other credentials to further our access deeper into the network. In this stage, we will typically use many techniques based on the information found on the exploited host or server.

#### Proof-of-Concept

In this stage, we document, step-by-step, the steps we took to achieve network compromise or some level of access. Our goal is to paint a picture of how we were able to chain together multiple weaknesses to reach our goal so they can see a clear picture of how each vulnerability fits in and help prioritize their remediation efforts. If we don't document our steps well, it's hard for the client to understand what we were able to do and, thus, makes their remediation efforts more difficult. If feasible, we could create one or more scripts to automate the steps we took to assist our client in reproducing our findings. We cover this in-depth in the `Documentation & Reporting` module.

#### Post-Engagement

During post-engagement, detailed documentation is prepared for both administrators and client company management to understand the severity of the vulnerabilities found. At this stage, we also clean up all traces of our actions on all hosts and servers. During this stage, we create the deliverables for our client, hold a report walkthrough meeting, and sometimes deliver an executive presentation to target company executives or their board of directors. Lastly, we will archive our testing data per our contractual obligations and company policy. We will typically retain this data for a set period or until we perform a post-remediation assessment (retest) to test the client's fixes.

* * *

## Importance

We must internalize this procedure and use it as a basis for all our technical engagements. Each stage's components allow us to precisely understand which areas we need to improve upon and where most of our difficulties and gaps in knowledge are. For example, we can think of a website as a target we need to study.

| **Stage** | **Description** |
| --- | --- |
| `1. Pre-Engagement` | The first step is to create all the necessary documents in the pre-engagement phase, discuss the assessment objectives, and clarify any questions. |
| `2. Information Gathering` | Once the pre-engagement activities are complete, we investigate the company's existing website we have been assigned to assess. We identify the technologies in use and learn how the web application functions. |
| `3. Vulnerability Assessment` | With this information, we can look for known vulnerabilities and investigate questionable features that may allow for unintended actions. |
| `4. Exploitation` | Once we have found potential vulnerabilities, we prepare our exploit code, tools, and environment and test the webserver for these potential vulnerabilities. |
| `5. Post-Exploitation` | Once we have successfully exploited the target, we jump into information gathering and examine the webserver from the inside. If we find sensitive information during this stage, we try to escalate our privileges (depending on the system and configurations). |
| `6. Lateral Movement` | If other servers and hosts in the internal network are in scope, we then try to move through the network and access other hosts and servers using the information we have gathered. |
| `7. Proof-of-Concept` | We create a proof-of-concept that proves that these vulnerabilities exist and potentially even automate the individual steps that trigger these vulnerabilities. |
| `8. Post-Engagement` | Finally, the documentation is completed and presented to our client as a formal report deliverable. Afterward, we may hold a report walkthrough meeting to clarify anything about our testing or results and provide any needed support to personnel tasked with remediating our findings. |


# Pre-Engagement

* * *

Pre-engagement is the stage of preparation for the actual penetration test. During this stage, many questions are asked, and some contractual agreements are made. The client informs us about what they want to be tested, and we explain in detail how to make the test as efficient as possible.

![Penetration testing process: Pre-Engagement, Information Gathering, Vulnerability Assessment, Exploitation, Post-Exploitation, Lateral Movement, Proof-of-Concept, Post-Engagement.](NHL61SGjrxnd.png)

The entire pre-engagement process consists of three essential components:

1. Scoping questionnaire

2. Pre-engagement meeting

3. Kick-off meeting


Before any of these can be discussed in detail, a `Non-Disclosure Agreement` ( `NDA`) must be signed by all parties. There are several types of NDAs:

| **Type** | **Description** |
| --- | --- |
| `Unilateral NDA` | This type of NDA obligates only one party to maintain confidentiality and allows the other party to share the information received with third parties. |
| `Bilateral NDA` | In this type, both parties are obligated to keep the resulting and acquired information confidential. This is the most common type of NDA that protects the work of penetration testers. |
| `Multilateral NDA` | Multilateral NDA is a commitment to confidentiality by more than two parties. If we conduct a penetration test for a cooperative network, all parties responsible and involved must sign this document. |

Exceptions can also be made in urgent cases, where we jump into the kick-off meeting, which can also occur via an online conference. It is essential to know `who in the company is permitted` to contract us for a penetration test. Because we cannot accept such an order from everyone. Imagine, for example, that a company employee hires us with the pretext of checking the corporate network's security. However, after we finished the assessment, it turned out that this employee wanted to harm their own company and had no authorization to have the company tested. This would put us in a critical situation from a legal point of view.

Below is a sample (not exhaustive) list of company members who may be authorized to hire us for penetration testing. This can vary from company to company, with larger organizations not involving the C-level staff directly and the responsibility falling on IT, Audit, or IT Security senior management or the like.

|  |  |  |
| --- | --- | --- |
| Chief Executive Officer (CEO) | Chief Technical Officer (CTO) | Chief Information Security Officer (CISO) |
| Chief Security Officer (CSO) | Chief Risk Officer (CRO) | Chief Information Officer (CIO) |
| VP of Internal Audit | Audit Manager | VP or Director of IT/Information Security |

It is vital to determine early on in the process who has signatory authority for the contract, Rules of Engagement documents, and who will be the primary and secondary points of contact, technical support, and contact for escalating any issues.

This stage also requires the preparation of several documents before a penetration test can be conducted that must be signed by our client and us so that the declaration of consent can also be presented in written form if required. Otherwise the penetration test could breach the [Computer Misuse Act](https://www.legislation.gov.uk/ukpga/1990/18/contents). These documents include, but are not limited to:

| **Document** | **Timing for Creation** |
| --- | --- |
| `1. Non-Disclosure Agreement` ( `NDA`) | `After` Initial Contact |
| `2. Scoping Questionnaire` | `Before` the Pre-Engagement Meeting |
| `3. Scoping Document` | `During` the Pre-Engagement Meeting |
| `4. Penetration Testing Proposal` ( `Contract/Scope of Work` ( `SoW`)) | `During` the Pre-engagement Meeting |
| `5. Rules of Engagement` ( `RoE`) | `Before` the Kick-Off Meeting |
| `6. Contractors Agreement` (Physical Assessments) | `Before` the Kick-Off Meeting |
| `7. Reports` | `During` and `after` the conducted Penetration Test |

Note: Our client may provide a separate scoping document listing in-scope IP addresses/ranges/URLs and any necessary credentials but this information should also be documented as an appendix in the RoE document.

**Important Note:**

These documents should be reviewed and adapted by a lawyer after they have been prepared.

* * *

## Scoping Questionnaire

After initial contact is made with the client, we typically send them a `Scoping Questionnaire` to better understand the services they are seeking. This scoping questionnaire should clearly explain our services and may typically ask them to choose one or more from the following list:

|  |  |
| --- | --- |
| ☐ Internal Vulnerability Assessment | ☐ External Vulnerability Assessment |
| ☐ Internal Penetration Test | ☐ External Penetration Test |
| ☐ Wireless Security Assessment | ☐ Application Security Assessment |
| ☐ Physical Security Assessment | ☐ Social Engineering Assessment |
| ☐ Red Team Assessment | ☐ Web Application Security Assessment |

Under each of these, the questionnaire should allow the client to be more specific about the required assessment. Do they need a web application or mobile application assessment? Secure code review? Should the Internal Penetration Test be black box and semi-evasive? Do they want just a phishing assessment as part of the Social Engineering Assessment or also vishing calls? This is our chance to explain the depth and breadth of our services, ensure that we understand our client's needs and expectations, and ensure that we can adequately deliver the assessment they require.

Aside from the assessment type, client name, address, and key personnel contact information, some other critical pieces of information include:

|  |  |
| --- | --- |
| How many expected live hosts? |  |
| How many IPs/CIDR ranges in scope? |  |
| How many Domains/Subdomains are in scope? |  |
| How many wireless SSIDs in scope? |  |
| How many web/mobile applications? If testing is authenticated, how many roles (standard user, admin, etc.)? |  |
| For a phishing assessment, how many users will be targeted? Will the client provide a list, or we will be required to gather this list via OSINT? |  |
| If the client is requesting a Physical Assessment, how many locations? If multiple sites are in-scope, are they geographically dispersed? |  |
| What is the objective of the Red Team Assessment? Are any activities (such as phishing or physical security attacks) out of scope? |  |
| Is a separate Active Directory Security Assessment desired? |  |
| Will network testing be conducted from an anonymous user on the network or a standard domain user? |  |
| Do we need to bypass Network Access Control (NAC)? |  |

Finally, we will want to ask about information disclosure and evasiveness (if applicable to the assessment type):

- Is the Penetration Test black box (no information provided), grey box (only IP address/CIDR ranges/URLs provided), white box (detailed information provided)

- Would they like us to test from a non-evasive, hybrid-evasive (start quiet and gradually become "louder" to assess at what level the client's security personnel detect our activities), or fully evasive.


This information will help us ensure we assign the right resources and deliver the engagement based on the client's expectations. This information is also necessary for providing an accurate proposal with a project timeline (for example, a Vulnerability Assessment will take considerably less time than a Red Team Assessment) and cost (an External Penetration Test against 10 IPs will cost significantly less than an Internal Penetration Test with 30 /24 networks in-scope).

Based on the information we received from the scoping questionnaire, we create an overview and summarize all information in the `Scoping Document`.

* * *

## Pre-Engagement Meeting

Once we have an initial idea of the client's project requirements, we can move on to the `pre-engagement meeting`. This meeting discusses all relevant and essential components with the customer before the penetration test, explaining them to our customer. The information we gather during this phase, along with the data collected from the scoping questionnaire, will serve as inputs to the `Penetration Testing Proposal`, also known as the `Contract` or `Scope of Work` ( `SoW`). We can think of the whole process as a visit to the doctor to inform ourselves regarding the planned examinations. This phase typically occurs via e-mail and during an online conference call or in-person meeting.

Note: We may encounter clients during our career that are undergoing their first ever penetration test, or the direct client PoC is not familiar with the process. It is not uncommon to use part of the pre-engagement meeting to review the scoping questionnaire either in part or step-by-step.

#### Contract - Checklist

| **Checkpoint** | **Description** |
| --- | --- |
| `☐ NDA` | Non-Disclosure Agreement (NDA) refers to a secrecy contract between the client and the contractor regarding all written or verbal information concerning an order/project. The contractor agrees to treat all confidential information brought to its attention as strictly confidential, even after the order/project is completed. Furthermore, any exceptions to confidentiality, the transferability of rights and obligations, and contractual penalties shall be stipulated in the agreement. The NDA should be signed before the kick-off meeting or at the latest during the meeting before any information is discussed in detail. |
| `☐ Goals` | Goals are milestones that must be achieved during the order/project. In this process, goal setting is started with the significant goals and continued with fine-grained and small ones. |
| `☐ Scope` | The individual components to be tested are discussed and defined. These may include domains, IP ranges, individual hosts, specific accounts, security systems, etc. Our customers may expect us to find out one or the other point by ourselves. However, the legal basis for testing the individual components has the highest priority here. |
| `☐ Penetration Testing Type` | When choosing the type of penetration test, we present the individual options and explain the advantages and disadvantages. Since we already know the goals and scope of our customers, we can and should also make a recommendation on what we advise and justify our recommendation accordingly. Which type is used in the end is the client's decision. |
| `☐ Methodologies` | Examples: OSSTMM, OWASP, automated and manual unauthenticated analysis of the internal and external network components, vulnerability assessments of network components and web applications, vulnerability threat vectorization, verification and exploitation, and exploit development to facilitate evasion techniques. |
| `☐ Penetration Testing Locations` | External: Remote (via secure VPN) and/or Internal: Internal or Remote (via secure VPN) |
| `☐ Time Estimation` | For the time estimation, we need the start and the end date for the penetration test. This gives us a precise time window to perform the test and helps us plan our procedure. It is also vital to explicitly ask how time windows the individual attacks (Exploitation / Post-Exploitation / Lateral Movement) are to be carried out. These can be carried out during or outside regular working hours. When testing outside regular working hours, the focus is more on the security solutions and systems that should withstand our attacks. |
| `☐ Third Parties` | For the third parties, it must be determined via which third-party providers our customer obtains services. These can be cloud providers, ISPs, and other hosting providers. Our client must obtain written consent from these providers describing that they agree and are aware that certain parts of their service will be subject to a simulated hacking attack. It is also highly advisable to require the contractor to forward the third-party permission sent to us so that we have actual confirmation that this permission has indeed been obtained. |
| `☐ Evasive Testing` | Evasive testing is the test of evading and passing security traffic and security systems in the customer's infrastructure. We look for techniques that allow us to find out information about the internal components and attack them. It depends on whether our contractor wants us to use such techniques or not. |
| `☐ Risks` | We must also inform our client about the risks involved in the tests and the possible consequences. Based on the risks and their potential severity, we can then set the limitations together and take certain precautions. |
| `☐ Scope Limitations & Restrictions` | It is also essential to determine which servers, workstations, or other network components are essential for the client's proper functioning and its customers. We will have to avoid these and must not influence them any further, as this could lead to critical technical errors that could also affect our client's customers in production. |
| `☐ Information Handling` | HIPAA, PCI, HITRUST, FISMA/NIST, etc. |
| `☐ Contact Information` | For the contact information, we need to create a list of each person's name, title, job title, e-mail address, phone number, office phone number, and an escalation priority order. |
| `☐ Lines of Communication` | It should also be documented which communication channels are used to exchange information between the customer and us. This may involve e-mail correspondence, telephone calls, or personal meetings. |
| `☐ Reporting` | Apart from the report's structure, any customer-specific requirements the report should contain are also discussed. In addition, we clarify how the reporting is to take place and whether a presentation of the results is desired. |
| `☐ Payment Terms` | Finally, prices and the terms of payment are explained. |

The most crucial element of this meeting is the detailed presentation of the penetration test to our client and its focus. As we already know, each piece of infrastructure is unique for the most part, and each client has particular preferences on which they place the most importance. Finding out these priorities is an essential part of this meeting.

We can think of it as ordering in a restaurant. If we want a medium-rare steak and the chef gives us a well-done steak because he believes it is better, it will not be what we were hoping for. Therefore, we should prioritize our client's wishes and serve the steak as they ordered.

Based on the `Contract Checklist` and the input information shared in scoping, the `Penetration Testing Proposal` ( `Contract`) and the associated `Rules of Engagement` ( `RoE`) are created.

#### Rules of Engagement - Checklist

| **Checkpoint** | **Contents** |
| --- | --- |
| `☐ Introduction` | Description of this document. |
| `☐ Contractor` | Company name, contractor full name, job title. |
| `☐ Penetration Testers` | Company name, pentesters full name. |
| `☐ Contact Information` | Mailing addresses, e-mail addresses, and phone numbers of all client parties and penetration testers. |
| `☐ Purpose` | Description of the purpose for the conducted penetration test. |
| `☐ Goals` | Description of the goals that should be achieved with the penetration test. |
| `☐ Scope` | All IPs, domain names, URLs, or CIDR ranges. |
| `☐ Lines of Communication` | Online conferences or phone calls or face-to-face meetings, or via e-mail. |
| `☐ Time Estimation` | Start and end dates. |
| `☐ Time of the Day to Test` | Times of the day to test. |
| `☐ Penetration Testing Type` | External/Internal Penetration Test/Vulnerability Assessments/Social Engineering. |
| `☐ Penetration Testing Locations` | Description of how the connection to the client network is established. |
| `☐ Methodologies` | OSSTMM, PTES, OWASP, and others. |
| `☐ Objectives / Flags` | Users, specific files, specific information, and others. |
| `☐ Evidence Handling` | Encryption, secure protocols |
| `☐ System Backups` | Configuration files, databases, and others. |
| `☐ Information Handling` | Strong data encryption |
| `☐ Incident Handling and Reporting` | Cases for contact, pentest interruptions, type of reports |
| `☐ Status Meetings` | Frequency of meetings, dates, times, included parties |
| `☐ Reporting` | Type, target readers, focus |
| `☐ Retesting` | Start and end dates |
| `☐ Disclaimers and Limitation of Liability` | System damage, data loss |
| `☐ Permission to Test` | Signed contract, contractors agreement |

* * *

## Kick-Off Meeting

The `kick-off meeting` usually occurs at a scheduled time and in-person after signing all contractual documents. This meeting usually includes client POC(s) (from Internal Audit, Information Security, IT, Governance & Risk, etc., depending on the client), client technical support staff (developers, sysadmins, network engineers, etc.), and the penetration testing team (someone in a management role (such as the Practice Lead), the actual penetration tester(s), and sometimes a Project Manager or even the Sales Account Executive or similar). We will go over the nature of the penetration test and how it will take place. Usually, there is no Denial of Service (DoS) testing. We also explain that if a critical vulnerability is identified, penetration testing activities will be paused, a vulnerability notification report will be generated, and the emergency contacts will be contacted. Typically these are only generated during External Penetration Tests for critical flaws such as unauthenticated remote code execution (RCE), SQL injection, or another flaw that leads to sensitive data disclosure. The purpose of this notification is to allow the client to assess the risk internally and determine if the issue warrants an emergency fix. We would typically only stop an Internal Penetration Test and alert the client if a system becomes unresponsive, we find evidence of illegal activity (such as illegal content on a file share) or the presence of an external threat actor in the network or a prior breach.

We must also inform our customers about potential risks during a penetration test. For example, we should mention that a penetration test can leave many `log entries and alarms` in their security applications. In addition, if brute forcing or any similar attack is used, it is also worth mentioning that we may accidentally `lock some users` found during the penetration test. We also must inform our customers that they must contact us immediately if the penetration test performed `negatively impacts their network`.

Explaining the penetration testing process gives everyone involved a clear idea of our entire process. This demonstrates our professional approach and convinces our questioners that we know what we are doing. Because apart from the technical staff, CTO, and CISO, it will sound like a certain kind of magic that is very difficult for non-technical professionals to understand. So we must be mindful of our audience and target the most technically inexperienced questioner so our approach can be followed by everyone we talk to.

All points related to testing need to be discussed and clarified. It is crucial to respond precisely to the wishes and expectations of the customer/client. Every company structure and network is different and requires an adapted approach. Each client has different goals, and we should adjust our testing to their wishes. We can typically see how experienced our clients are in undergoing penetration tests early in the call, so we may have to shift our focus to explain things in more detail and be prepared to field more questions, or the kickoff call may be very quick and straightforward.

* * *

## Contractors Agreement

If the penetration test also includes physical testing, then an additional contractor's agreement is required. Since it is not only a virtual environment but also a physical intrusion, completely different laws apply here. It is also possible that many of the employees have not been informed about the test. Suppose we encounter employees with a very high-security awareness during the physical attack and social engineering attempts, and we get caught. In that case, the employees will, in most cases, contact the police. This additional `contractor's agreement` is our " `get out of jail free card`" in this case.

#### Contractors Agreement - Checklist for Physical Assessments

| **Checkpoint** |
| --- |
| `☐ Introduction` |
| `☐ Contractor` |
| `☐ Purpose` |
| `☐ Goal` |
| `☐ Penetration Testers` |
| `☐ Contact Information` |
| `☐ Physical Addresses` |
| `☐ Building Name` |
| `☐ Floors` |
| `☐ Physical Room Identifications` |
| `☐ Physical Components` |
| `☐ Timeline` |
| `☐ Notarization` |
| `☐ Permission to Test` |

* * *

## Setting Up

After all the above points have been worked through, and we have the necessary information, we plan our approach and prepare everything. We will find that the penetration test results are still unknown, but we can prepare our VMs, VPS, and other tools/systems for all scenarios and situations. More information and how to prepare these systems can be found in the [Setting Up](https://academy.hackthebox.com/module/details/87) module.

Enable step-by-step solutions for all questions
![sparkles-icon-decoration](CbiU9HUlgKG0)

#### Questions

Answer the question(s) below
to complete this Section and earn cubes!

\+ 2  How many documents must be prepared in total for a penetration test?


Submit


# Information Gathering

* * *

Once the pre-engagement phase has been completed, and all parties have signed all contractual terms and conditions, the `information gathering` phase begins. Information gathering is an essential part of any security assessment. This is the phase in which we gather all available information about the company, its employees and infrastructure, and how they are organized. Information gathering is the most frequent and vital phase throughout the penetration testing process, to which we will return again and again.

![Penetration testing process: Pre-Engagement, Information Gathering, Vulnerability Assessment, Exploitation, Post-Exploitation, Lateral Movement, Proof-of-Concept, Post-Engagement.](s0KToYQUcpY5.png)

All the steps we take to exploit the vulnerabilities are based on the information we enumerate about our targets. This phase can be considered the cornerstone of any penetration test. We can obtain the necessary information relevant to us in many different ways. However, we can divide them into the following categories:

- Open-Source Intelligence
- Infrastructure Enumeration
- Service Enumeration
- Host Enumeration

All four categories should and must be performed by us for each penetration test. This is because the `information` is the main component that leads us to successful penetration testing and identifying security vulnerabilities. We can get this information anywhere, whether on social media, job postings, individual hosts and servers, or even the employees. Information is continually being spread and shared everywhere.

After all, we humans communicate by exchanging information, but network components and services communicate similarly. Any exchange of information always has a specific purpose. For computer networks, the aim is always to trigger a particular process. Be it storing data in a database, registering, generating specific values, or forwarding the information.

* * *

## Open-Source Intelligence

Let's assume that our client wants us to see what information we can find about his company on the internet. For this purpose, we use what is known as `Open Source Intelligence` ( `OSINT`). OSINT is a process for finding publicly available information on a target company or individuals that allows the identification of events (i.e., public and private meetings), external and internal dependencies, and connections. OSINT uses public (Open-Source) information from freely available sources to obtain the desired results. We can often find security-relevant and sensitive information from companies and their employees. Usually, the people who share such information are unaware that they are not the only ones who can access it.

It is possible to find highly sensitive information such as passwords, hashes, keys, tokens, and much more that can give us access to the network within just a few minutes. Repositories on sites like [Github](https://github.com/) or other development platforms are often not set up correctly, and external viewers can see this information. If this type of sensitive information is found at the onset of testing, the Incident Handling and Report section of the RoE should describe the procedure for reporting these types of critical security vulnerabilities. Publicly published passwords or SSH keys represent a critical security gap if they have not already been removed or changed. Therefore, our client's administrator must review this information before we proceed.

#### Private and Public SSH Keys

![Searchcode page showing code snippet with redacted OpenSSH private and public keys.](3QNWBw0FDd1Q.png)

Developers often share whole sections of code on [StackOverflow](https://stackoverflow.com/) to show other developers a better overview of how their code works to help them solve their problems. This type of information can also be found very quickly and used against the company. Our task is to find such security holes and have them closed. We can learn much more from the [OSINT: Corporate Recon](https://academy.hackthebox.com/course/preview/osint-corporate-recon) module. It shows many different techniques for how we can find such information.

* * *

## Infrastructure Enumeration

During the infrastructure enumeration, we try to overview the company's position on the internet and intranet. For this, we use OSINT and the first active scans. We use services such as DNS to create a map of the client's servers and hosts and develop an understanding of how their `infrastructure` is structured. This includes name servers, mail servers, web servers, cloud instances, and more. We make an accurate list of hosts and their IP addresses and compare them to our scope to see if they are included and listed.

In this phase, we also try to determine the company's security measures. The more precise this information is, the easier it will be to disguise our attacks ( `Evasive Testing`). But identifying firewalls, such as web application firewalls, also gives us an excellent understanding of what techniques could trigger an alarm for our customer and what methods can be used to avoid that alarm.

Here, it also does not matter "where" we are positioned, whether we are trying to gain an overview of the infrastructure from the outside ( `external`) or examining the infrastructure from the inside ( `internal`) of the network. Enumeration from inside the network gives us a good overview of the hosts and servers that we can use as targets for a `Password Spraying` attack, in which we use one password to attempt to authenticate with as many different user names as possible, hoping for one successful authentication attempt to grant us a foothold in the network. All these methods and techniques used for this purpose will be looked at in more detail in the individual modules.

* * *

## Service Enumeration

In service enumeration, we identify services that allow us to interact with the host or server over the network (or locally, from an internal perspective). Therefore, it is crucial to find out about the service, what `version` it is, what `information` it provides us, and the `reason` it can be used. Once we understand the background of what this service has been provisioned for, some logical conclusions can be drawn to provide us with several options.

Many services have a version history that allows us to identify whether the installed version on the host or server is actually up to date or not. This will also help us find security vulnerabilities that remain with older versions in most cases. Many administrators are afraid to change applications that work, as it could harm the entire infrastructure. Therefore, administrators often prefer to accept the risk of leaving one or more vulnerabilities open and maintaining the functionality instead of closing the security gaps.

* * *

## Host Enumeration

Once we have a detailed list of the customer's infrastructure, we examine every single host listed in the scoping document. We try to identify which `operating system` is running on the host or server, which `services` it uses, which `versions` of the services, and much more. Again, apart from the active scans, we can also use various OSINT methods to tell us how this host or server may be configured.

We can find many different services, such as an FTP server that the company uses to exchange data between employees and even allows anonymous access. Even today, there are many hosts and servers that the manufacturers no longer support. However, vulnerabilities are still found for these older versions of operating systems and services, which then remain and endanger our client's entire infrastructure.

It does not matter here whether we examine each host or server externally or internally. However, from the internal perspective, we will find services that are often not accessible from the outside. Therefore, many administrators become careless and often consider these services "secure" because they are not directly accessible from the internet. Thus, many misconfigurations are often discovered here due to these assumptions or lax practices. During host enumeration, we try to determine what role this host or server plays and what network components it communicates with. In addition, we must also identify which `services` it uses for this purpose and on which `ports` they are located.

During internal host enumeration, which in most cases comes after the successful `Exploitation` of one or more vulnerabilities, we also examine the host or server from the inside. This means we look for sensitive `files`, local `services`, `scripts`, `applications`, `information`, and other things that could be stored on the host. This is also an essential part of the `Post-Exploitation` phase, where we try to exploit and elevate privileges.

* * *

## Pillaging

Another essential step is `Pillaging`. After hitting the `Post-Exploitation` stage, pillaging is performed to collect sensitive information locally on the already exploited host, such as employee names, customer data, and much more. However, this information gathering only occurs after exploiting the target host and gaining access to it.

The information we can obtain on the exploited hosts can be divided into many different categories and varies greatly. This depends on the purpose of the host and its positioning in the corporate network. The administrators taking the security measures for these hosts also play a significant role. Nevertheless, such information can show the `impact` of a potential attack on our client and be used for further steps to `escalate our privileges` or `move laterally` further in the network.

- Note that `HTB Academy` does not have a module explicitly focused on pillaging.

This is intentional for reasons we will clarify here. Pillaging alone is not a stage or a subcategory as many often describe but an integral part of the information gathering and privilege escalation stages that is inevitably performed locally on target systems.

- `Pillaging is explained in other modules separately, where we consider the corresponding steps valuable and necessary.`

Here is a small list of modules where `Pillaging` is covered, but this topic will be covered in many other modules as well:

|  |  |  |
| --- | --- | --- |
| `Network Enumeration with Nmap` | `Getting Started` | `Password Attacks` |
| `Active Directory Enumeration & Attacks` | `Linux Privilege Escalation` | `Windows Privilege Escalation` |
| `Attacking Common Services` | `Attacking Common Applications` | `Attacking Enterprise Networks` |

We will interact with more than `150 targets` during the Penetration Tester Job Role Path and perform nine simulated mini penetration tests, giving us plenty of opportunities to work on and practice this topic. Furthermore, operating system-specific modules should be considered from the pillaging point of view because much of what is shown in those modules can be used for information retrieval or privilege escalation on the target systems.


# Vulnerability Assessment

* * *

During the `vulnerability assessment` phase, we examine and analyze the information gathered during the information gathering phase. The vulnerability assessment phase is an analytical process based on the findings.

![Penetration testing process: Pre-Engagement, Information Gathering, Vulnerability Assessment, Exploitation, Post-Exploitation, Lateral Movement, Proof-of-Concept, Post-Engagement.](9hhEuwNKgPwz.png)

`An analysis is a detailed examination of an event or process, describing its origin and impact, that with the help of certain precautions and actions, can be triggered to support or prevent future occurrences.`

Any analysis can be very complicated, as many different factors and their interdependencies play a significant role. Apart from the fact that we work with the three different times (past, present, and future) during each analysis, the origin and destination play a significant role. There are four different types of analysis:

| **Analysis Type** | **Description** |
| --- | --- |
| `Descriptive` | Descriptive analysis is essential in any data analysis. On the one hand, it describes a data set based on individual characteristics. It helps to detect possible errors in data collection or outliers in the data set. |
| `Diagnostic` | Diagnostic analysis clarifies conditions' causes, effects, and interactions. Doing so provides insights that are obtained through correlations and interpretation. We must take a backward-looking view, similar to descriptive analysis, with the subtle difference that we try to find reasons for events and developments. |
| `Predictive` | By evaluating historical and current data, predictive analysis creates a predictive model for future probabilities. Based on the results of descriptive and diagnostic analyses, this method of data analysis makes it possible to identify trends, detect deviations from expected values at an early stage, and predict future occurrences as accurately as possible. |
| `Prescriptive` | Prescriptive analytics aims to narrow down what actions to take to eliminate or prevent a future problem or trigger a specific activity or process. |

We use our results and information obtained so far and analyze them to make conclusions. The formation of conclusions can be extended very far, but we must then confirm or disprove them. Suppose we found an open TCP port 2121 on a host during the information-gathering phase.

Other than the fact that this port is open, Nmap did not show us anything else. We must now ask ourselves what conclusions can be drawn from this result. Therefore, it does not matter which question we start with to make our conclusions. However, it is essential to ask `precise questions` and remember what we `know` and `do not know`. At this point, we must first ask ourselves what we `see` and what we actually `have`, because what we see is not the same as what we have:

- a `TCP` port `2121`. \- `TCP` already means that this service is `connection-oriented`.

- Is this a `standard` port? - `No`, because these are between `0-1023`, aka well-known or [system ports](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)

- Are there any numbers in this `port number` that look `familiar`? \- `Yes`, `TCP` port `21` ( `FTP`). From our experience, we will get to know many standard ports and their services, which administrators often try to disguise, but often use "easy to remember" alternatives.


Based on our guess, we can try to connect to the service using `Netcat` or an `FTP` client and try to establish a connection to confirm or disprove our guess.

While connecting to the service, we noticed that the connection took longer than usual (about 15 seconds). There are some services whose connection speed, or response time, can be configured. Now that we know that an FTP server is running on this port, we can deduce the origin of our "failed" scan. We could confirm this again by specifying the minimum `probe round trip time` ( `--min-rtt-timeout`) in Nmap to 15 or 20 seconds and rerunning the scan.

* * *

## Vulnerability Research and Analysis

`Information Gathering` and `Vulnerability Research` can be considered a part of descriptive analysis. This is where we identify the individual network or system components we are investigating. In `Vulnerability Research`, we look for known vulnerabilities, exploits, and security holes that have already been discovered and reported. Therefore, if we have identified a version of a service or application through information gathering and found a [Common Vulnerabilities and Exposures (CVE)](https://www.cve.org/ResourcesSupport/FAQs), it is very likely that this vulnerability is still present.

We can find vulnerability disclosures for each component using many different sources. These include, but are not limited to:

|  |  |  |
| --- | --- | --- |
| [CVEdetails](https://www.cvedetails.com/) | [Exploit DB](https://www.exploit-db.com) | [Vulners](https://vulners.com) |
| [Packet Storm Security](https://packetstormsecurity.com) | [NIST](https://nvd.nist.gov/vuln/search?execution=e2s1) |  |

This is where `Diagnostic Analysis` and `Predictive Analysis` is used. Once we have found a published vulnerability like this, we can diagnose it to determine what is causing or has caused the vulnerability. Here, we must understand the functionality of the `Proof-Of-Concept` ( `POC`) code or the application or service itself as best as possible, as many manual configurations by administrators will require some customization for the POC. Each POC is tailored to a specific case that we will also need to adapt to ours in most cases.

* * *

## Assessment of Possible Attack Vectors

`Vulnerability Assessment` also includes the actual testing, which is part of `Predictive Analysis`. In doing so, we analyze historical information and combine it with the current information that we have been able to find out. Whether we have received specific evasion level requirements from our client, we test the services and applications found `locally` or `on the target system`. If we have to test covertly and avoid alerts, we should mirror the target system locally as precisely as possible. This means we use the information obtained during our information gathering phase to replicate the target system and then look for vulnerabilities in the locally deployed system.

* * *

## The Return

Suppose we are unable to detect or identify potential vulnerabilities from our analysis. In that case, we will return to the `Information Gathering` stage and look for more in-depth information than we have gathered so far. It is important to note that these two stages ( `Information Gathering` and `Vulnerability Assessment`) often overlap, resulting in regular back and forth movement between them. We will see this in many videos where the author is solving an HTB box or some CTF challenge. We should remember that these challenges are often solved as fast as possible, and therefore speed is more important than quality. In a CTF, the goal is to get on the target machine and `capture the flags` with the highest privileges as fast as possible instead of exposing all potential weaknesses in the system.

| **`A (real) Penetration Test is not a CTF.`** |
| --- |

Here the `quality` and `intensity` of our penetration test and its analysis have the highest priority because nothing is worse if our client gets successfully hacked via a relatively simple vector that we should have uncovered during our penetration test.

Enable step-by-step solutions for all questions
![sparkles-icon-decoration](nhoyoyRpt6zM)

#### Questions

Answer the question(s) below
to complete this Section and earn cubes!

\+ 2  What type of analysis can be used to predict future probabilities?


Submit


# Exploitation

* * *

During the `Exploitation` stage, we look for ways that these weaknesses can be adapted to our use case to obtain the desired role (i.e., a foothold, escalated privileges, etc.). If we want to get a reverse shell, we need to modify the PoC to execute the code, so the target system connects back to us over (ideally) an encrypted connection to an IP address we specify. Therefore, the preparation of an exploit is mainly part of the `Exploitation` stage.

![Penetration testing process: Pre-Engagement, Information Gathering, Vulnerability Assessment, Exploitation, Post-Exploitation, Lateral Movement, Proof-of-Concept, Post-Engagement.](V8tMU25B58Ab.png)

These stages should not be strictly separated from each other, as they are closely connected. Nevertheless, it is still important to distinguish which phase we are in and its purpose. Because later, with much more complex processes and much more information, it is very easy to lose track of the steps that have been taken, especially if the penetration test lasts several weeks and covers a massive scope.

* * *

## Prioritization of Possible Attacks

Once we have found one or two vulnerabilities during the `Vulnerability Assessment` stage that we can apply to our target network/system, we can prioritize those attacks. Which of those attacks we prioritize higher than the others depends on the following factors:

- Probability of Success
- Complexity
- Probability of Damage

First, we need to assess the `probability of successfully` executing a particular attack against the target. [CVSS Scoring](https://nvd.nist.gov/vuln-metrics/cvss) can help us here, using the [NVD calculator](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator) better to calculate the specific attacks and their probability of success.

`Complexity` represents the effort of exploiting a specific vulnerability. This is used to estimate how much time, effort, and research is required to execute the attack on the system successfully. Our experience plays an important role here because if we are to carry out an attack that we have never used before, this will logically require much more research and effort since we must understand the attack and the exploit structure in detail before applying it.

Estimating the `probability of damage` caused by the execution of an exploit plays a critical role, as we must avoid any damage to the target systems. Generally, we do not perform DoS attacks unless our client requires them. Nevertheless, attacking the running services live with exploits that can cause damage to the software or the operating system is something that we must avoid at all times.

In addition, we can assign these factors to a personal point system which will allow the evaluation to be more accurately calculated based on our skills and knowledge:

#### Prioritization Example

| **Factor** | **Points** | **Remote File Inclusion** | **Buffer Overflow** |
| --- | --- | --- | --- |
| 1\. Probability of Success | `10` | 10 | 8 |
| 2\. Complexity - Easy | `5` | 4 | 0 |
| 3\. Complexity - Medium | `3` | 0 | 3 |
| 4\. Complexity - Hard | `1` | 0 | 0 |
| 5\. Probability of Damage | `-5` | 0 | -5 |
| **Summary** | `max. 15` | 14 | 6 |

Based on the above example, we would prefer the `remote file inclusion` attack. It is easy to prepare and execute and should not cause any damage if approached carefully.

* * *

## Preparation for the Attack

Sometimes we will run into a situation where we can't find high-quality, known working PoC exploit code. Therefore, it may be necessary to reconstruct the exploit locally on a VM representing our target host to figure out precisely what needs to be adapted and changed. Once we have set up the system locally and installed known components to mirror the target environment as closely as possible (i.e., same version numbers for target services/applications), we can start preparing the exploit by following the steps described in the exploit. Then we test this on a locally hosted VM to ensure it works and does not damage significantly. In other situations, we will encounter misconfigurations and vulnerabilities that we see very often and know exactly which tool or exploit to use and whether the exploit or technique is "safe" or can cause instability.

If ever in doubt before running an attack, it's always best to check with our client, providing them all necessary data so they can make an informed decision on whether they would like us to attempt exploitation or just mark the finding as an issue. If they opt for us not to proceed with exploitation, we can note in the report that it was not confirmed actively but is likely an issue that needs to be addressed. We have a certain amount of leeway during penetration tests and should always use our best judgment if a particular attack seems too risky or could potentially cause a disruption. When in doubt, communicate. Your team lead/manager, the client, will almost certainly prefer extra communication than run into a situation where they are trying to bring a system back online after a failed exploit attempt.

Once we have successfully exploited a target and have initial access (and taken clear notes for our reports and logged all activities in our activity log!), we'll move on to the post-exploitation and lateral movement stages.


# Post-Exploitation

* * *

Let's assume we successfully exploited the target system during the `Exploitation` stage. As with the Exploitation stage, we must again consider whether or not to utilize `Evasive Testing` in the `Post-Exploitation` stage. We are already on the system in the post-exploitation phase, making it much more difficult to avoid an alert. The `Post-Exploitation` stage aims to obtain sensitive and security-relevant information from a local perspective and business-relevant information that, in most cases, requires higher privileges than a standard user. This stage includes the following components:

|  |  |
| --- | --- |
| Evasive Testing | Information Gathering |
| Pillaging | Vulnerability Assessment |
| Privilege Escalation | Persistence |
| Data Exfiltration |  |

![Penetration testing process: Pre-Engagement, Information Gathering, Vulnerability Assessment, Exploitation, Post-Exploitation, Lateral Movement, Proof-of-Concept, Post-Engagement.](RXDiT8HxqMXF.png)

* * *

## Evasive Testing

If a skilled administrator monitors the systems, any change or even a single command could trigger an alarm that will give us away. In many cases, we get kicked out of the network, and then threat hunting begins where we are the focus. We may also lose access to a host (that gets quarantined) or a user account (that gets temporarily disabled or the password changed). This penetration test would have failed but succeeded in some ways because the client could detect some actions. We can provide value to the client in this situation by still writing up an entire attack chain and helping them identify gaps in their monitoring and processes where they did not notice our actions. For us, we can study how and why the client detected us and work on improving our evasion skills. Perhaps we did not thoroughly test a payload, or we got careless and ran a command such as `net user` or `whoami` that is often monitored by EDR systems and flagged as anomalous activity.

It can often help our clients if we run commands or tools that their defenses stop or detect. It shows them that their defenses are working on some attacks. Keep in mind that we are emulating an attacker, so it's not always entirely bad for some of the attacks to get noticed. Though when performing evasive testing, our goal should be to go mostly undetected so we can identify any "blind spots" our clients have in their network environments.

Evasive testing is divided into three different categories:

| **`Evasive`** | **`Hybrid Evasive`** | **`Non-Evasive`** |
| --- | --- | --- |

This does not mean that we cannot use all three methods. Suppose our client wants to perform an intrusive penetration test to get as much information as possible and the most in-depth testing results. In that case, we will perform `Non-Evasive` Testing, as the security measures around the network may limit and even stop us. However, this can also be combined with `Evasive` testing, using the same commands and methods for non-evasive testing. We can then see if the security measures can identify and respond to the actions performed. In `Hybrid-Evasive` testing, we can test specific components and security measures that have been defined in advance. This is common when the customer only wants to test specific departments or servers to see if they can withstand the attacks.

* * *

## Information Gathering

Since we have gained a new perspective on the system and the network of our target system in the Exploitation stage, we are basically in a new environment. This means we first have to reacquaint ourselves with what we are working with and what options are available. Therefore, in the `Post-Exploitation` stage, we go through the `Information Gathering` and `Vulnerability Assessment` stages again, which we can consider as parts of the current stage. This is because the information we had up to this point was gathered from an external perspective, not an internal one.

From the inside (local) perspective, we have many more possibilities and alternatives to access certain information that is relevant to us. Therefore, the information gathering stage starts all over again from the local perspective. We search and gather as much information as we can. The difference here is that we also enumerate the local network and local services such as printers, database servers, virtualization services, etc. Often we will find shares intended for employees to use to exchange and share data and files. The investigation of these services and network components is called `Pillaging`.

* * *

## Pillaging

Pillaging is the stage where we examine the role of the host in the corporate network. We analyze the network configurations, including but not limited to:

|  |  |  |
| --- | --- | --- |
| Interfaces | Routing | DNS |
| ARP | Services | VPN |
| IP Subnets | Shares | Network Traffic |

`Understanding the role of the system` we are on also gives us an excellent understanding of how it communicates with other network devices and its purpose. From this, we can find out, for example, what alternative subdomains exist, whether it has multiple network interfaces, whether there are other hosts with which this system communicates, if admins are connecting to other hosts from it, and if we can potentially reuse credentials or steal an SSH key to further our access or establish persistence, etc. This helps, above all, to get an overview of the network's structure.

For example, we can use the policies installed on this system to determine what other hosts are using on the network. Because administrators often use particular schemas to secure their network and prevent users from changing anything on it. For example, suppose we discover that the password policy requires only eight characters but no special characters. In that case, we can conclude that we have a relatively high probability of guessing other users' passwords on this and other systems.

During the pillaging stage, we will also hunt for sensitive data such as passwords on shares, local machines, in scripts, configuration files, password vaults, documents (Excel, Word, .txt files, etc.), and even email.

Our main goals with pillaging are to show the impact of successful exploitation and, if we have not yet reached the goal of the assessment, to find additional data such as passwords that can be inputs to other stages such as lateral movement.

* * *

## Persistence

Once we have an overview of the system, our immediate next step is maintaining access to the exploited host. This way, if the connection is interrupted, we can still access it. This step is essential and often used as the first step before the `Information Gathering` and `Pillaging` stages.

We should follow non-standardized sequences because each system is individually configured by a unique administrator who brings their own preferences and knowledge. It is recommended that we `work flexibly` during this phase `and adapt` to the circumstances. For example, suppose we have used a buffer overflow attack on a service that is likely to crash it. In that case, we should establish persistence to the system as soon as possible to avoid having to attack the service multiple times and potentially causing a disruption. Often if we lose the connection, we will not be able to access the system in the same way.

* * *

## Vulnerability Assessment

If we can maintain access and have a good overview of the system, we can use the information about the system and its services and any other data stored on it to repeat the `Vulnerability Assessment` stage, but this time from inside the system. We analyze the information and prioritize it accordingly. The goal we pursue next is the escalation of privileges (if not already in place).

Again, it is essential to distinguish between exploits that can harm the system and attacks against the services that do not cause any disruption. In doing so, we weigh the components we have already gone through in the first Vulnerability Assessment stage.

* * *

## Privilege Escalation

Privilege escalation is significant, and in most cases, it represents a critical moment that can open many more new doors for us. Getting the highest possible privileges on the system or domain is often crucial. Therefore we want to get the privileges of the `root` (on `Linux-based` systems) or the domain `administrator`/ `local administrator`/ `SYSTEM` (on `Windows-based` systems) because this will often allow us to move through the entire network without any restrictions.

However, it is essential to remember that the escalation of privileges does not always have to occur locally on the system. We can also obtain stored credentials during the information gathering stage from other users who are members of a higher privileged group. Exploiting these privileges to log in as another user is also part of privilege escalation because we have escalated our privileges (quickly) using the new set of credentials.

* * *

## Data Exfiltration

During the `Information Gathering` and `Pillaging` stage, we will often be able to find, among other things, considerable personal information and customer data. Some clients will want to check whether it is possible to exfiltrate these types of data. This means we try to transfer this information from the target system to our own. Security systems such as `Data Loss Prevention` ( `DLP`) and `Endpoint Detection and Response` ( `EDR`) help detect and prevent data exfiltration. In addition to `Network Monitoring`, many companies use encryption on hard drives to prevent external parties from viewing such information. Before exfiltrating any actual data, we should check with the customer and our manager. It can often be enough to create some bogus data (such as fake credit card numbers or social security numbers) and exfiltrate it to our system. That way, the protection mechanisms that look for patterns in data leaving the network will be tested, but we will not be responsible for any live sensitive data on our testing machine.

Companies must adhere to data security regulations depending on the type of data involved. These include, but are not limited to:

| **Type of Information** | **Security Regulation** |
| --- | --- |
| Credit Card Account Information | `Payment Card Industry` ( `PCI`) |
| Electronic Patient Health Information | `Health Insurance Portability and Accountability Act` ( `HIPAA`) |
| Consumers Private Banking Information | `Gramm-Leach-Bliley` ( `GLBA`) |
| Government Information | `Federal Information Security Management Act of 2002` ( `FISMA`) |

Some frameworks companies may follow include:

|  |  |
| --- | --- |
| ( `NIST`) \- National Institute of Standards and Technology | ( `CIS Controls`) \- Center for Internet Security Controls |
| ( `ISO`) \- International Organization for Standardization | ( `PCI-DSS`) \- The Payment Card Industry Data Security Standard |
| ( `GDPR`) \- General Data Protection Regulation | ( `COBIT`) \- Control Objectives for Information and Related Technologies |
| ( `FedRAMP`) \- The Federal Risk and Authorization Management Program | ( `ITAR`) \- International Traffic in Arms Regulations |
| ( `AICPA`) \- American Institute of Certified Public Accountants | ( `NERC CIP Standards`) \- NERC Critical Infrastructure Protection Standards |

It is worth familiarizing ourselves with each of these frameworks but what is crucial for us, however, is how we handle this information. For us, the type of data does not have much significance, but the required controls around it do, and as stated previously, we can simulate exfiltrating data from the network as a proof of concept that it is possible. We should check with the client to ensure that their systems are intended to catch the fake data type that we attempt to exfiltrate if we are successful, so we do not misrepresent anything in our report.

It's a good habit to run a screen recording (along with taking screenshots) as additional evidence for such vital steps. If we only have terminal access, we can display the hostname, IP address, user name, and the corresponding path to the customer file and take a screenshot or screen capture. This helps us prove where the data originated from and that we could remove it from the environment successfully.

If sensitive data like this is found, our client should, of course, be informed immediately. Based on the fact that we could escalate the privileges and exfiltrate personal data, they may want to pause, end, or shift the focus of the penetration test, especially if data exfiltration was the primary goal. However, this is at our client's discretion, and many will prefer that we keep testing to identify all possible weaknesses in their environment.

Next, we'll discuss lateral movement, a key stage in the penetration testing process that may use data from our post-exploitation as an input.

Enable step-by-step solutions for all questions
![sparkles-icon-decoration](9wX4tFkXwAKw)

#### Questions

Answer the question(s) below
to complete this Section and earn cubes!

\+ 2  How many types of evasive testing are mentioned in this section?


Submit


\+ 2  What is the name of the security standard for credit card payments that a company must adhere to? (Answer Format: acronym)


Submit


# Lateral Movement

* * *

If everything went well and we were able to penetrate the corporate network ( `Exploitation`) successfully, gather locally stored information, and escalate our privileges ( `Post-Exploitation`), we next enter the `Lateral Movement` stage. The goal here is that we test what an attacker could do within the entire network. After all, the main goal is not only to successfully exploit a publicly available system but also to get sensitive data or find all ways that an attacker could render the network unusable. One of the most common examples is [ransomware](https://www.csoonline.com/article/3236183/what-is-ransomware-how-it-works-and-how-to-remove-it.html). If a system in the corporate network is infected with ransomware, it can spread across the entire network. It locks down all the systems using various encryption methods, making them unusable for the whole company until a decryption key is entered.

In the most common cases, the company is financially extorted to make a profit. Often, it is only at this moment that companies realize how important IT security is. If they had had a good penetration tester who had tested things (and proper processes and layered defenses in place), they probably could have prevented such a situation and the financial (if not legal) damage. It is often forgotten that in many countries, the `CEOs are held liable` for not securing their customer data appropriately.

![Penetration testing process: Pre-Engagement, Information Gathering, Vulnerability Assessment, Exploitation, Post-Exploitation, Lateral Movement, Proof-of-Concept, Post-Engagement.](Sgko2xjYgCti.png)

In this stage, we want to test how far we can move manually in the entire network and what vulnerabilities we can find from the internal perspective that might be exploited. In doing so, we will again run through several phases:

1. Pivoting
2. Evasive Testing
3. Information Gathering
4. Vulnerability Assessment
5. (Privilege) Exploitation
6. Post-Exploitation

As seen in the graphic above, we can move to this stage from the `Exploitation` and the `Post-Exploitation` stage. Sometimes we may not find a direct way to escalate our privileges on the target system itself, but we have ways to move around the network. This is where `Lateral Movement` comes into play.

* * *

## Pivoting

In most cases, the system we use will not have the tools to enumerate the internal network efficiently. Some techniques allow us to use the exploited host as a proxy and perform all the scans from our attack machine or VM. In doing so, the exploited system represents and routes all our network requests sent from our attack machine to the internal network and its network components.

In this way, we make sure that non-routable networks (and therefore publicly unreachable) can still be reached. This allows us to scan them for vulnerabilities and penetrate deeper into the network. This process is also known as `Pivoting` or `Tunneling`.

An elementary example could be that we have a printer at home that is not accessible from the Internet, but we can send print jobs from our home network. If one of the hosts on our home network has been compromised, it could be leveraged to send these jobs to the printer. Though this is a simple (and unlikely) example, it illustrates the goal of `pivoting`, which is to access inaccessible systems via an intermediary system.

* * *

## Evasive Testing

Also, at this stage, we should consider whether evasive testing is part of the assessment scope. There are different procedures for each tactic, which support us in disguising these requests to not trigger an internal alarm among the administrators and the blue team.

There are many ways to protect against lateral movement, including network (micro) `segmentation`, `threat monitoring`, `IPS`/ `IDS`, `EDR`, etc. To bypass these efficiently, we need to understand how they work and what they respond to. Then we can adapt and apply methods and strategies that help avoid detection.

* * *

## Information Gathering

Before we target the internal network, we must first get an `overview` of which systems and how many can be reached from our system. This information may already be available to us from the last post-exploitation stage, where we took a closer look at the settings and configurations of the system.

We return to the Information Gathering stage, but this time, we do it from inside the network with a different view of it. Once we have discovered all hosts and servers, we can enumerate them individually.

* * *

## Vulnerability Assessment

Vulnerability assessment from the inside of the network differs from the previous procedures. This is because far more errors occur inside a network than on hosts and servers exposed to the Internet. Here, the `groups` to which one has been assigned and the `rights` to different system components play an essential role. In addition, it is common for users to share information and documents and work on them together.

This type of information is of particular interest to us when planning our attacks. For example, if we compromise a user account assigned to a developer group, we may gain access to most of the resources used by company developers. This will likely provide us with crucial internal information about the systems and could help us to identify flaws or further our access.

* * *

## (Privilege) Exploitation

Once we have found and prioritized these paths, we can jump to the step where we use these to access the other systems. We often find ways to crack passwords and hashes and gain higher privileges. Another standard method is to use our existing credentials on other systems. There will also be situations where we do not even have to crack the hashes but can use them directly. For example, we can use the tool [Responder](https://github.com/lgandx/Responder) to intercept NTLMv2 hashes. If we can intercept a hash from an administrator, then we can use the `pass-the-hash` technique to log in as that administrator (in most cases) on multiple hosts and servers.

After all, the `Lateral Movement` stage aims to move through the internal network. Existing data and information can be versatile and often used in many ways.

* * *

## Post-Exploitation

Once we have reached one or more hosts or servers, we go through the steps of the post-exploitation stage again for each system. Here we again collect system information, data from created users, and business information that can be presented as evidence. However, we must again consider how this different information must be handled and the rules defined around sensitive data in the contract.

Finally, we are ready to move on to the `Proof-of-Concept` phase to show off our hard work and help our client, and those responsible for remediation efficiently reproduce our results.


# Proof-of-Concept

* * *

`Proof of Concept` ( `PoC`) or `Proof of Principle` is a project management term. In project management, it serves as proof that a project is feasible in principle. The criteria for this can lie in technical or business factors. Therefore, it is the basis for further work, in our case, the necessary steps to secure the corporate network by confirming the discovered vulnerabilities. In other words, it serves as a decision-making basis for the further course of action. At the same time, it enables risks to be identified and minimized.

![Penetration testing process: Pre-Engagement, Information Gathering, Vulnerability Assessment, Exploitation, Post-Exploitation, Lateral Movement, Proof-of-Concept, Post-Engagement.](LngaMkEAgI0p.png)

This project step is often integrated into the development process for new application software (prototyping) or IT security solutions. For us in information security, this is where we prove vulnerabilities in operating systems or application software. We use this PoC to prove that a security problem exists so that the developers or administrators can validate it, reproduce it, see the impact, and test their remediation efforts. One of the most common examples used to prove software vulnerabilities is executing the calculator (calc.exe on Windows) on the target system. In principle, the PoC also assesses the probability of success of system access from actual exploitation.

A `PoC` can have many different representations. For example, `documentation` of the vulnerabilities found can also constitute a PoC. The more practical version of a PoC is a `script` or `code` that automatically exploits the vulnerabilities found. This demonstrates the flawless exploitation of the vulnerabilities. This variant is straightforward for an administrator or developer because they can see what steps our script takes to exploit the vulnerability.

However, there is one significant disadvantage that has occurred from time to time. Once the administrators and developers have received such a script from us, it is easy for them to "fight" against our script. They focus on changing the systems so that the script we created no longer works. The important thing is that the script is only `one way` of exploiting a given vulnerability. Therefore, working against our script instead of with it and modifying and securing the systems so that our script no longer works does not mean that the information obtained from the script cannot be obtained in another way. It is an important aspect that should be discussed with the administrators and developers and explicitly mentioned and pointed out.

The report they receive from us should help them see the entire picture, focus on the broader issues, and provide clear remediation advice. Including an attack chain walkthrough in the event of domain compromise during an internal is a great way to show how multiple flaws can be combined and how fixing one flaw will break the chain, but the other flaws will still exist. If these are not also fixed, there may be another path to get to the point where the attack chain was remediated and continue onwards. We should also drive this point home during our report review meeting.

For example, if a user uses the password `Password123`, the underlying vulnerability is not the password but the `password policy`. If a Domain Admin is found to be using that password and it is changed, that one account will now have a stronger password, but the problem of weak passwords will likely still be endemic within the organization.

If the password policy followed high standards, the user would not be able to use such a weak password. Administrators and developers are responsible for the functionality and the quality of their systems and applications. Furthermore, high quality stands for high standards, which we should emphasize through our remediation recommendations.


# Post-Engagement

Much like there is considerable legwork before an engagement officially starts (when testing begins), we must perform many activities (many of them contractually binding) after our scans, exploitation, lateral movement, and post-exploitation activities are complete. No two engagements are the same, so these activities may differ slightly but generally must be performed to close out an engagement fully.

![Penetration testing process: Pre-Engagement, Information Gathering, Vulnerability Assessment, Exploitation, Post-Exploitation, Lateral Movement, Proof-of-Concept, Post-Engagement.](4UGDxMH7LuRG.png)

* * *

## Cleanup

Once testing is complete, we should perform any necessary cleanup, such as deleting tools/scripts uploaded to target systems, reverting any (minor) configuration changes we may have made, etc. We should have detailed notes of all of our activities, making any cleanup activities easy and efficient. If we cannot access a system where an artifact needs to be deleted, or another change reverted, we should alert the client and list these issues in the report appendices. Even if we can remove any uploaded files and revert changes (such as adding a local admin account), we should document these changes in our report appendices in case the client receives alerts that they need to follow up on and confirm that the activity in question was part of our sanctioned testing.

* * *

## Documentation and Reporting

Before completing the assessment and disconnecting from the client's internal network or sending "stop" notification emails to signal the end of testing (meaning no more interaction with the client's hosts), we must make sure to have adequate documentation for all findings that we plan to include in our report. This includes command output, screenshots, a listing of affected hosts, and anything else specific to the client environment or finding. We should also make sure that we have retrieved all scan and log output if the client hosted a VM in their infrastructure for an internal penetration test and any other data that may be included as part of the report or as supplementary documentation. We should not keep any Personal Identifiable Information (PII), potentially incriminating info, or other sensitive data we came across throughout testing.

We should already have a detailed list of the findings we will include in the report and all necessary details to tailor the findings to the client's environment. Our report deliverable (which is covered in detail in the [Documentation & Reporting](https://academy.hackthebox.com/module/details/162) module) should consist of the following:

- An attack chain (in the event of full internal compromise or external to internal access) detailing steps taken to achieve compromise
- A strong executive summary that a non-technical audience can understand
- Detailed findings specific to the client's environment that include a risk rating, finding impact, remediation recommendations, and high-quality external references related to the issue
- Adequate steps to reproduce each finding so the team responsible for remediation can understand and test the issue while putting fixes in place
- Near, medium, and long-term recommendations specific to the environment
- Appendices which include information such as the target scope, OSINT data (if relevant to the engagement), password cracking analysis (if relevant), discovered ports/services, compromised hosts, compromised accounts, files transferred to client-owned systems, any account creation/system modifications, an Active Directory security analysis (if relevant), relevant scan data/supplementary documentation, and any other information necessary to explain a specific finding or recommendation further

At this stage, we will create a draft report that is the first deliverable our client will receive. From here, they will be able to comment on the report and ask for any necessary clarification/modifications.

* * *

## Report Review Meeting

Once the draft report is delivered, and the client has had a chance to distribute it internally and review it in-depth, it is customary to hold a report review meeting to walk through the assessment results. The report review meeting typically includes the same folks from the client and the firm performing the assessment. Depending on the types of findings, the client may bring in additional technical subject matter experts if the finding is related to a system or application they are responsible for. Typically we will not read the entire report word for word but walk through each finding briefly and give an explanation from our own perspective/experience. The client will have the opportunity to ask questions about anything in the report, ask for clarifications, or point out issues that need to be corrected. Often the client will come with a list of questions about specific findings and will not want to cover every finding in detail (such as low-risk ones).

* * *

## Deliverable Acceptance

The Scope of Work should clearly define the acceptance of any project deliverables. In penetration test assessments, generally, we deliver a report marked `DRAFT` and give the client a chance to review and comment. Once the client has submitted feedback (i.e., management responses, requests for clarification/changes, additional evidence, etc.) either by email or (ideally) during a report review meeting, we can issue them a new version of the report marked `FINAL`. Some audit firms that clients may be beholden to will not accept a penetration test report with a `DRAFT` designation. Other companies will not care, but keeping a uniform approach across all customers is best.

* * *

## Post-Remediation Testing

Most engagements include post-remediation testing as part of the project's total cost. In this phase, we will review any documentation provided by the client showing evidence of remediation or just a list of remediated findings. We will need to reaccess the target environment and test each issue to ensure it was appropriately remediated. We will issue a post-remediation report that clearly shows the state of the environment before and after post-remediation testing. For example, we may include a table such as:

| # | Finding Severity | Finding Title | Status |
| --- | --- | --- | --- |
| 1 | High | SQL Injection | Remediated |
| 2 | High | Broken Authentication | Remediated |
| 3 | High | Unrestricted File Upload | Remediated |
| 4 | High | Inadequate Web and Egress Filtering | Not Remediated |
| 5 | Medium | SMB Signing Not Enabled | Not Remediated |
| 6 | Low | Directory Listing Enabled | Not Remediated |

For each finding (where possible), we will want to show evidence that the issue is no longer present in the environment through scan output or proof that the original exploitation techniques fail.

* * *

## Role of the Pentester in Remediation

Since a penetration test is essentially an audit, we must remain impartial third parties and not perform remediation on our findings (such as fixing code, patching systems, or making configuration changes in Active Directory). We must maintain a degree of independence and can serve as trusted advisors by giving general remediation advice on how a specific issue could be fixed or be available to explain further/demonstrate a finding so the team assigned to remediate it has a better understanding. We should not be implementing changes ourselves or even giving precise remediation advice (i.e., for SQL Injection, we may say "sanitize user input" but not give the client a rewritten piece of code). This will help maintain the assessment's integrity and not introduce any potential conflict of interest into the process.

* * *

## Data Retention

After a penetration test concludes, we will have a considerable amount of client-specific data such as scan results, log output, credentials, screenshots, and more. Data retention and destruction requirements may differ from country to country and firm to firm, and procedures surrounding each should be outlined clearly in the contract language of the Scope of Work and the Rules of Engagement. Per [Penetration Testing Guidance](https://www.pcisecuritystandards.org/documents/Penetration_Testing_Guidance_March_2015.pdf) from the PCI Data Security Standard (PCI DSS):

"While there are currently no PCI DSS requirements regarding the retention of evidence collected by the
penetration tester, it is a recommended best practice that the tester retain such evidence
(whether internal to the organization or a third-party provider) for a period of time while considering any
local, regional, or company laws that must be followed for the retention of evidence. This evidence should
be available upon request from the target entity or other authorized entities as defined in the rules of
engagement."

We should retain evidence for some time after the penetration test in case questions arise about specific findings or to assist with retesting "closed" findings after the client has performed remediation activities. Any data retained after the assessment should be stored in a secure location owned and controlled by the firm and encrypted at rest. All data should be wiped from tester systems at the conclusion of an assessment. A new virtual machine specific to the client in question should be created for any post-remediation testing or investigation of findings related to client inquiries.

* * *

## Close Out

Once we have delivered the final report, assisted the client with questions regarding remediation, and performed post-remediation testing/issued a new report, we can finally close the project. At this stage, we should ensure that any systems used to connect to the client's systems or process data have been wiped or destroyed and that any artifacts leftover from the engagement are stored securely (encrypted) per our firm's policy and per contractual obligations to our client. The final steps would be invoicing the client and collecting payment for services rendered. Finally, it is always good to follow up with a post-assessment client satisfaction survey so the team and management, in particular, can see what went well during the engagement and what could be improved upon from a company process standpoint and the individual consultant assigned to the project. Discussions for follow-on work may arise in the weeks or months after if the client was pleased with our work and day-to-day interactions.

As we continually grow our technical skillset, we should always look for ways to improve our soft skills and become more well-rounded professional consultants. In the end, the `client will usually remember interactions` during the assessment, communication, and how they were treated/valued by the firm they engage, `not the fancy exploit chain the pentester pulled off to pwn their systems`. Take this time to self-reflect and work on continuous improvement in all aspects of your role as a professional penetration tester.

Enable step-by-step solutions for all questions
![sparkles-icon-decoration](uvufWCTBclhs)

#### Questions

Answer the question(s) below
to complete this Section and earn cubes!

\+ 2  What designation do we typically give a report when it is first delivered to a client for a chance to review and comment? (One word)


Submit


# Practice

* * *

All the theories in the world will be of no use to us if we cannot transfer them into practice and apply our knowledge to real-world, hands-on situations. Putting the Tactics, Techniques, and Procedures (TTPs) we have covered in the Penetration Tester path into use frequently is the best thing we could do to keep our skills sharp and ensure that when it comes time to put them to work in a customer's environment, we are sure of ourselves and the potential impact our actions may have. Technical skills are only half the battle, however. We also need excellent written and verbal communication skills to be effective penetration testers. This includes seemingly minor things like being able to write a clear and professional email and present and defend our work during a client meeting and through a professional report.

You will often find yourself working with a team in this field, and as a team, we can help each other grow and hone our skills. Need to practice leading a kickoff call with a customer? Have a friend or teammate act as a fictitious customer. Use that time to practice asking your initial scoping questions and defining the pentest you expect to deliver. These same actions can be used when practicing delivering your post-engagement report walkthrough briefing for a client.

Penetration testing is fun. We get to attack a network and act like real-world hackers for a period of time. What some people may find boring, however, is an essential part: thorough documentation and strong reporting skills. A client won't be able to do much with a vague two-page report (the same way a two-section module wouldn't do you much good). If we were contracted by a Fortune 500 company and able to take control of their entire domain without triggering an alarm, we'll need to be able to prove it. If we can't back up our assertions with clear evidence, we'll lose credibility, and our work will be called into question.

Similarly, if we have 50+ pages of documentation, we have considerably more evidence to back up our work and we're more likely to make an impression on the decision-makers in the client company. That being said, if our presentation is sloppy and the report is difficult to follow or does not go in-depth on vulnerability reproduction steps and give clear remediation recommendations, or the executive summary is poorly written, our hard work will not be well-received. Documentation and reporting (including how to write a high-quality report) will be covered in another module. This module also gives many suggestions and resources for practicing this critical soft skill.

Note: When working on a pentest team, we would often practice client kickoff calls and report review meetings with each other. We practiced reviewing the results and drilled each other on our report content and the recommendations we gave to our clients. When our clients asked questions or disputed our recommendations, we were prepared to handle the situation and could answer clearly on the spot as to why we would recommend a specific fix. This type of practice will surely give you a more polished and professional look.

As crucial as the client-facing portions of a penetration test are, they won't much matter if we don't practice our hands-on keyboard skills. Practicing will help us see what comes naturally to us and what areas we need to improve. Reading is not a replacement for hands-on practice (though written theory is crucial for developing a deep understanding of the myriad of topics we cover). Once certain tasks become second nature through considerable practice, we will save time and energy that can be used to dig deep on client assessments or for our own research and analysis.

We may be wizards in web exploitation but struggle when facing an Active Directory environment. Ideally, you will practice in lab environments that match your clients. ( If you often pentest against organizations that use specific equipment like the medical field, ideally, you will have replications of common devices you could encounter to test against.) But that's not always feasible. So what can you do? Well, in Hack The Box, we have many different ways for you to hone your skills. Everything from the active machines to challenges to Prolabs and Battlegrounds can be used to get further hands-on experience dealing with all classes of vulnerabilities. The modules here in HTB Academy provide an excellent resource to practice our skills. Many of the modules in the Penetration Tester Job Role Path feature labs that can be approached as mock penetration tests. This repetition may be tedious on the front end, but it will save countless hours that we can use to continue improving. The steps below can help guide us on a path to practicing what we have learned:

* * *

## Practicing Steps

Think about the skills you have gained and what interests you the most from them. From there, we can pick out a few more modules to increase our knowledge, machines to practice on, and Prolabs or Endgames to really put ourselves to the test. The numbers below are a good starting example:

- 2x Modules
- 3x Retired Machines
- 5x Active Machines
- 1x Pro Lab / Endgame

#### Modules

The modules chosen should be categorized according to `two different difficulties`: `technical` and `offensive`. We use these to familiarize ourselves with the attacks and the possibilities and develop an accurate picture and understanding of those attacks. Then we use the provided exercises and their machines to learn to apply these techniques and, at the same time to create efficient `notes` and `screenshots` for accurate ` documentation`. Here is a good blueprint for tackling a module:

| **Step** | **Task** |
| --- | --- |
| 1. | Read the module |
| 2. | Practice the exercises |
| 3. | Complete the module |
| 4. | Start the module exercises from scratch |
| 5. | While solving the exercises again, take notes |
| 6. | Create technical documentation based on the notes |
| 7. | Create non-technical documentation based on the notes |

The selection of several modules allows us to deal with different technologies and issues we may face. We will discover various aspects that need to be considered and sometimes documented/notated in more detail than before. These notes will be quite valuable as we move along in our careers. Some pairings of technologies and attack vectors can be rare to see in the wild, so having detailed notes about those systems from when you interacted with them will help you progress through an assessment quicker where you encounter them.

After completing the module, we should create minor `technical` and `non-technical` documentation (i.e., create sample technical findings and reproduction steps and executive summary entries that could be included in a report). Focus on practicing creating "client-ready" documentation. Many people underestimate the amount of knowledge and skills that are imprinted through the creation of the documentation. Practicing writing documentation can help cement some topics in our minds and make it easier for us to explain concepts to both technical and non-technical audiences.

#### Retired Machines

When we have completed (at least) two modules and are satisfied with our notes and documentation, we can select three different retired machines. These should also differ in difficulty, but we recommend choosing `two easy` and `one medium` machines. At the end of each module, you will find recommended retired machines to consider that will help you practice the specific tools and topics covered in the module. These hosts will share one or more attack vectors tied to the module.

With the retired machines, we have a significant advantage in that we can find existing write-ups online from many different authors (all with varying approaches) with which we can compare our notes. If we opt to purchase a VIP membership on the HTB main platform, we will also have access to official HTB write-ups that present another viewpoint and often include some defensive considerations. We can use these write-ups to compare whether we have noted everything necessary and have not overlooked anything. The order in which we can proceed to practice with the retired machines looks something like this:

| **Step** | **Task** |
| --- | --- |
| 1. | Get the user flag on your own |
| 2. | Get the root flag on your own |
| 3. | Write your technical documentation |
| 4. | Write your non-technical documentation |
| 5. | Compare your notes with the official write-up (or a community write-up if you don't have a VIP subscription |
| 6. | Create a list of information you have missed |
| 7. | Watch [Ippsec's](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA) walkthrough and compare it with your notes |
| 8. | Expand your notes and documentation by adding the missed parts |

Finally, we should create `technical` and `non-technical` documentation again. We will find that this one will likely be more extensive than the previous ones because we are working with many more topics we need to cover and document here. The most significant advantage of this approach is that we go through the entire penetration testing process, improving the way we capture essential information and have everything we need to prepare our documentation based on our experiences and notes.

#### Active Machines

After building a good foundation with the modules and the retired machines, we can venture to `two easy`, `two medium`, and `one hard` active machine. We can also take these from the corresponding module recommendations at the end of each module in Academy.

The advantage of this method is that we simulate as realistic a situation as possible using a single host that we have no familiarity with and cannot find documentation on (blackbox approach). As long as the machine remains active, no official write-ups will be published. This means that we cannot check whether we have everything or whether we have missed something from any official source. This puts us in the situation of relying on ourselves and our abilities. Ideal practice steps for active machines would look like this:

| **Step** | **Task** |
| --- | --- |
| 1. | Get the user and root flag |
| 2. | Write your technical documentation |
| 3. | Write your non-technical documentation |
| 4. | Have it proofread by technical and non-technical persons |

Proofreading gives us our first impressions of how the readers receive the two types of documentation. This gives us an idea of which aspects of our documentation need to be improved for both technical and non-technical audiences. As we can already imagine, not many non-technical people are interested in reading this type of documentation. Therefore, we need to design the non-technical documentation to be `informative`, `high quality`, and kept `concise` but meaningful and free of highly technical jargon. More about this is covered in the [Documentation & Reporting](https://academy.hackthebox.com/module/details/162) module.

#### Pro Lab/Endgame

Once we feel comfortable going against singular hosts and documenting our findings, we can take on Prolabs and Endgames. These labs are large multi-host environments that often simulate enterprise networks of varying sizes similar to those we could run into during actual penetration tests for our clients. This will present us with different challenges than we are used to. We will no longer be focusing on a single host and now have to consider how the different hosts interact with each other. These interactions will make for new and interesting vectors we can potentially practice against as well. For example, running a tool like `Responder` in an Active Directory environment to see traffic and capture a user's password hash or some sort of user interaction is much more likely in a simulated network than when attacking a single box. Attacking infrastructure with several interconnected hosts and network components will create additional connections we need to consider in our documentation. Instead of showing how to complete a single host from start to finish, we will need to practice writing up an entire attack chain, showing our path from foothold to network compromise. This, again, is covered in the `Documentation & Reporting` module. The practice we have from the previous tasks will make this much easier for us as everything builds on each other.

* * *

# Wrapping Up

We have covered a considerable amount of information in this module. If you are just beginning the `Penetration Tester` Job Role path, we recommend continuing in the order in which the modules are presented. If we are new to all this, skipping around could lead to gaps in knowledge and make certain modules difficult to finish without prerequisite knowledge. If you are already partially through the path, it's worth going back through modules that you have already completed and consider the various steps in the context of the penetration testing process presented in this module.

Continuous practice and improvement are vital regardless of where you are in your journey. We can continuously improve on our current methodology, learn things differently, and learn new concepts. The field of information technology changes rapidly. New attacks are discovered frequently, and we need to stay on top of the latest and greatest TTPs to be as effective as possible and provide our clients with the necessary information to help secure their environments from an ever-evolving threat landscape. Never stop learning and improving. Challenge yourself daily. Take breaks. Enjoy the journey, and don't forget to `Think Outside The Box`!


