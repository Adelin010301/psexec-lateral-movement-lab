# Screenshots

Place your screenshots in this folder using the filenames below — `case-study.md` already references these exact names, so once you drop the files in and rename them, the images will render automatically on GitHub.

| Filename | What it should show |
|---|---|
| `01-lab-topology.png` | Your lab network diagram (pfSense/LAN/OPT1/Splunk/target/attacker) — from your GitHub README diagram, or a fresh export |
| `02-nmap-filtered.png` | The `nmap -Pn -p 445` scan showing `445/tcp filtered microsoft-ds` |
| `03-nmap-open.png` | The re-scan showing `445/tcp open microsoft-ds` after the firewall profile fix |
| `04-share-access-denied.png` | Terminal output showing `share 'ADMIN$' is not writable` / `share 'C$' is not writable` |
| `05-psexec-success.png` | Terminal output showing `Found writable share ADMIN$`, `Uploading file`, `Creating service`, `Starting service` |
| `06-sysmon-event3-network.png` | Splunk search result for Sysmon EventCode=3 (network connection) |
| `07-sysmon-event11-filecreate.png` | Splunk search result for Sysmon EventCode=11 showing `TargetFilename: C:\Windows\ufHkjTiA.exe` |
| `08-system-event7045-service.png` | Splunk search result for System EventCode=7045 showing `Service Name: MtlW` |
| `09-sysmon-event1-process.png` | Splunk search result for Sysmon EventCode=1 showing `ParentImage: C:\Windows\System32\services.exe` |
| `10-defender-detection.png` | Windows Security Center screenshot showing `VirTool:Win32/RemoteExec` flagged Severe |
| `11-alert-config.png` | Splunk "Save As Alert" configuration screen (search, schedule, trigger condition) |
| `12-alert-triggered.png` | Splunk **Activity → Triggered Alerts** entry showing the alert fired |

## Notes

- Crop screenshots to the relevant window/pane where possible — full-desktop screenshots with multiple windows are harder to read once embedded in GitHub's markdown renderer.
- If any screenshot contains a real password or other sensitive value in plaintext (some of your terminal captures did during this exercise), redact it with a black box or crop it out before committing.
- PNG or JPG both work fine; keep file sizes reasonable (a few hundred KB each) so the repo stays lightweight.
