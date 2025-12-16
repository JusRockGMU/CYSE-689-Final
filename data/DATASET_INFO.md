# Pentest Report Generator - Dataset Information

## Dataset Source
**Repository**: [InfoSecWarrior/Vulnerable-Box-Resources](https://github.com/InfoSecWarrior/Vulnerable-Box-Resources)
**License**: Public repository for educational pentesting
**Collection Date**: December 13, 2025

## Dataset Description
We have collected **20 Nmap XML scan files** from well-documented vulnerable virtual machines. These machines are commonly used in cybersecurity training and CTF challenges, with known vulnerabilities documented in walkthroughs and security databases.

## Machines Included

| Machine Name | Size | Known For |
|-------------|------|-----------|
| Metasploitable-2 | 26K | Intentionally vulnerable Linux VM, extensively documented |
| Kioptrix-Level-1.1 | 14K | Classic pentesting training machine |
| Digitalworld-local-JOY | 34K | Modern CTF machine with web vulnerabilities |
| Vulnix | 30K | NFS and privilege escalation challenges |
| Stapler-1 | 15K | Multiple exploitation paths |
| Devguru | 15K | Web application vulnerabilities |
| DerpNStink-1 | 6.9K | WordPress-based vulnerabilities |
| Bob-1.0.1 | 5.9K | Simple beginner-friendly machine |
| Prime-1 | 5.9K | Web enumeration challenges |
| Tommy-Boy | 6.7K | Fun themed CTF machine |
| Troll-1 | 7.9K | Misdirection and persistence |
| BSides-Vancouver-2018 | 7.6K | Conference CTF challenge |
| Lord-Of-The-Root-1.0.1 | 8.8K | Privilege escalation focused |
| Pinkys-Palace-v1 | 6.1K | Buffer overflow and shell |
| SpyderSec | 6.6K | Web exploitation |
| Temple-Of-Doom | 5.7K | Custom service vulnerabilities |
| Wintermute-Straylight | 8.6K | Advanced exploitation |
| Zico2 | 8.8K | LFI and code injection |
| Chronos | 6.4K | Node.js vulnerabilities |
| Typo-1 | 8.0K | CMS vulnerabilities |

## Ground Truth Labeling Strategy

Since no pre-labeled vulnerability reports exist, we use a **self-labeling approach**:

1. **Documented Vulnerabilities**: Each machine has public walkthroughs documenting expected vulnerabilities
2. **Known CVEs**: Services with version numbers can be cross-referenced with CVE databases
3. **Fact-based Validation**: We validate LLM claims against parsed Nmap facts (ports, services, versions)

## Evaluation Approach

Rather than precision/recall requiring manual labels, we measure:

1. **Fact-Grounding Rate**: % of LLM findings citing actual Nmap facts
2. **Hallucination Detection**: Claims about non-existent ports/services
3. **Evidence Completeness**: Coverage of all discovered services

## Data Format

Each XML file contains:
- Open ports and their states
- Service names and versions
- Operating system detection
- NSE script outputs
- Banner information

## Ethical Considerations

- All scans are from intentionally vulnerable VMs designed for training
- No live systems were scanned
- Data is publicly available for educational purposes
- Following ethical pentesting guidelines
