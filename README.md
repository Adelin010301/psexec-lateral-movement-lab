# PsExec Lateral Movement — Detection & Response Case Study

A hands-on home SOC lab exercise simulating PsExec-style lateral movement (SMB / remote service execution) against a segmented Windows target, with full detection validation across Sysmon, native Windows event logs, and Splunk — including a scheduled detection alert.

## What's in this repo

| File | Description |
|---|---|
| [`case-study.md`](./case-study.md) | Full write-up: attack narrative, detection evidence, Splunk alert build, and recommended response actions |
| [`screenshots/`](./screenshots) | Supporting evidence — terminal output, Splunk searches, Windows Defender detection, alert configuration |

## Summary

This exercise covers the full lifecycle of a lateral movement attack in a lab environment:

- **Reconnaissance** — port scanning to identify SMB exposure
- **Defense interaction** — diagnosing and adjusting a Windows Firewall network profile blocking SMB (Public → Private), and UAC Remote Restrictions blocking admin share access
- **Exploitation** — PsExec-style remote execution via Impacket, from a Kali Linux attacker host to a Windows 10 target
- **Detection** — full-chain correlation across Sysmon (network connection, file creation, process creation) and native Windows Service Control Manager logging (service installation), independently corroborated by a real-time Windows Defender detection
- **Detection engineering** — a scheduled Splunk alert built to catch this technique going forward, not just a one-time investigative search

## Lab environment

| Component | Details |
|---|---|
| Firewall / segmentation | pfSense — LAN (192.168.10.0/24), isolated management network OPT1 (192.168.20.0/24) |
| SIEM | Splunk Enterprise, on Ubuntu |
| Target | Windows 10, Sysmon + Splunk Universal Forwarder installed |
| Attacker | Kali Linux |
| Endpoint protection | Windows Defender (default configuration) |

All hosts run in an isolated VirtualBox lab network with no route to production or external systems.

## MITRE ATT&CK mapping

- [T1021.002 — Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [T1569.002 — System Services: Service Execution](https://attack.mitre.org/techniques/T1569/002/)

## Related work

- [Botium Toys — NIST CSF Security Audit](https://github.com/Adelin010301)
- [Phishing Email Incident Report](https://github.com/Adelin010301)

---
**Author:** Norbert Adelin Fratutiu — [GitHub](https://github.com/Adelin010301) · [LinkedIn](https://linkedin.com/in/adelin-fratutiu-07406a195)
