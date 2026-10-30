# AppSentry for M365 – LinkedIn Teaser (DE & EN)

![AppSentry LinkedIn Banner](../assets/appsentry-linkedin-banner.png)

---

## 🇩🇪 DEUTSCH: LinkedIn Post Teaser

**Wissen Sie eigentlich, welche OAuth-Apps in Ihrem Microsoft 365 Tenant heimlich eigene Passwörter erstellen oder Admin-Rollen kapern dürfen?** 🤖🛡️

Supply-Chain-Angriffe über kompromittierte Drittanbieter-Apps (wie jüngst *ConnectWise / SkyKick*, *Midnight Blizzard* oder zweckentfremdete *LotL Admin-CLIs*) gehören aktuell zu den gefährlichsten Einfallstoren in Microsoft Entra ID.

Das Problem: Einmal erteilte App-Berechtigungen (`Application.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`) überleben jeden Passwort-Reset und umgehen jedes MFA!

Deshalb stelle ich heute **AppSentry for M365** als **100 % kostenloses Open-Source-Tool (MIT)** für die Community bereit:

✅ **Nur lesende Berechtigungen im Scan:** Keine Schreibrechte im Tenant erforderlich.
✅ **3-Block Sicherheits- & Compliance-Architektur:**
1️⃣ **14 Globale Tenant-Schutzeinstellungen (`T-01` bis `T-14`):** Prüft User Consent, App-Erstellungsrechte, `defaultAppManagementPolicy` (Passwort-Sperren für Apps/Service Principals) inkl. Entra Audit-Log-Nachweis (*Wer hat wann welche Einstellung geändert?*).
2️⃣ **Prominente 24-Monats Threat-Intelligence Watchlist (23 Apps):** Prüft Ihren Tenant gezielt auf derzeit bekannte kompromittierte Drittanbieter-Apps, OAuth-Phishing-Kampagnen und ungehärtete Admin-CLIs – inklusive **grünem Negativhinweis** für Auditoren & Geschäftsführung!
3️⃣ **Umfassendes App-Inventar & 6-Dimensionen-Ampel:** Kann überprivilegierte Apps, Hintertür-Secrets auf fremden Enterprise Apps und fehlende Publisher-Verifizierung.
✅ **3-Stufen Soft-Lockdown Generator (`-WhatIf` First):** Generiert auf Knopfdruck fertige PowerShell-Skripte (Graph SDK & REST) mit **Live-Verifizierung** – vom sanften Soft-Lockdown ohne Datenverlust (Stufe 1) bis zur Notfall-Quarantäne (Stufe 3).
✅ **Kann bei NIS2, DORA & ISO 27001 unterstützen:** Zweisprachiges (DE/EN) Offline-HTML-Dashboard inkl. druckfertigem DIN-A4 Management-Bericht.

🔗 **GitHub Repository (Open Source):** https://github.com/MKN1411/AppSentry-for-M365
🌐 **Blog & Hintergrundartikel:** https://www.security-and-compliance.pro/blog/

Wie prüfen Sie aktuell Ihre Enterprise Applications auf Supply-Chain-Risiken? Ich freue mich auf Ihr Feedback! 👇

#Microsoft365 #EntraID #CyberSecurity #NIS2 #ISO27001 #CloudSecurity #PowerShell #OpenSource #AppSentry #CISO

---

## 🇬🇧 ENGLISH: LinkedIn Post Teaser

**Do you actually know which OAuth apps in your Microsoft 365 tenant can silently mint their own client secrets or hijack directory roles?** 🤖🛡️

Supply-chain compromises via third-party applications (such as recent *ConnectWise / SkyKick* incidents, *Midnight Blizzard*, or unhardened *LotL Admin CLIs*) have become one of the most dangerous initial access and persistence vectors in Microsoft Entra ID.

The catch: Once granted, high-privilege app roles (`Application.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`) bypass MFA and survive every user password reset!

Today, I’m excited to release **AppSentry for M365** as a **100% free & open-source tool (MIT)** for the security community:

✅ **Read-Only Assessment:** Zero write permissions required during scanning.
✅ **3-Block Security & Audit Architecture:**
1️⃣ **14 Global Tenant Protection Policies (`T-01` to `T-14`):** Evaluates User Consent, app creation rights, and `defaultAppManagementPolicy` password restrictions — complete with Entra Directory Audit Log attribution (*Who changed what and when?*).
2️⃣ **Prominent 24-Month Threat Intelligence Watchlist (23 Apps):** Screens your tenant against currently known vendor breaches, adversary-in-the-middle OAuth apps, and LotL CLIs — including a **Green Negative Hint (no guarantee)** for CISO & board reporting!
3️⃣ **Full App Inventory & 6-Pillar Traffic-Light Scoring:** Detects privilege escalation paths, rogue client secrets on foreign service principals, and unverified publishers.
✅ **3-Stage Soft-Lockdown Playbook Generator (`-WhatIf` by default):** Generates ready-to-run PowerShell remediation scripts (Graph SDK & REST) with built-in **Live State Verification** — from non-destructive Stage 1 Soft-Lockdown to Stage 3 Hard Quarantine.
✅ **Kann bei NIS2, DORA & ISO 27001 unterstützen:** Self-contained bilingual (EN/DE) HTML dashboard with one-click A4 PDF/Print Executive Report.

🔗 **GitHub Repository (Open Source):** https://github.com/MKN1411/AppSentry-for-M365
🌐 **Security & Compliance Blog:** https://www.security-and-compliance.pro/blog/

How are you currently auditing Enterprise Applications and OAuth supply-chain risks in Entra ID? Let me know in the comments! 👇

#Microsoft365 #EntraID #CyberSecurity #SupplyChainSecurity #NIS2 #DORA #ISO27001 #PowerShell #OpenSource #AppSentry #CISO

