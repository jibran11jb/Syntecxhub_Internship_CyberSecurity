# Responsible Disclosure & Triage Basics

## Rules of engagement
1. Only scan systems you own or have **written** permission to test (scope, dates, IP ranges).
2. Stop at *detection*. Do not exploit, exfiltrate data, or disrupt services to "prove" a finding.
3. Keep findings confidential until the owner has had time to fix.

## Triage workflow
| Step | Question | Action |
|---|---|---|
| 1. Validate | Is the version string real? Back-ported fix? | Check package changelog / vendor advisory, run `-V`, compare with CVE affected ranges |
| 2. Score | CVSS base score? | Use NVD; adjust for environment (internet-facing? auth required?) |
| 3. Exploitability | Public exploit? In CISA KEV? | KEV or public PoC → raise priority |
| 4. Impact | What data/system is behind it? | Crown-jewel systems first |
| 5. Decide | Patch / mitigate / accept risk | Record owner + deadline |

Suggested SLAs: Critical 24–48 h · High 7 days · Medium 30 days · Low next cycle.

## Disclosing a vulnerability you found in someone else's product
1. Look for `security.txt` (`/.well-known/security.txt`), a bug-bounty page, or `security@` address; use CERT/CC or the national CERT if there is no contact.
2. Send a **private** report: affected product/version, clear reproduction steps (non-destructive), impact, suggested fix, your contact info.
3. Agree on a timeline (industry norm ≈ 90 days; shorter if actively exploited).
4. Do not publish exploit details before a patch is available (coordinated disclosure). Request a CVE ID via the vendor or MITRE/CNA if appropriate.
5. Keep records of all communication.

## Report template
```
Title:        <short description>
Product:      <name + version>
Severity:     <CVSS vector/score + your rationale>
Description:  <what is wrong and why it matters>
Steps:        <minimal, non-destructive steps to verify>
Impact:       <what an attacker could do>
Mitigation:   <patch / config change>
Timeline:     <date found, date reported, agreed disclosure date>
```
