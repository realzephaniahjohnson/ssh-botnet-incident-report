# Hunting and detection queries

These are the queries we used during the investigation. They all run in [Mothlight's](https://mothlight.streamlit.app) Search console against the `honeypot` table, and the results below are what we actually got on Nov 9, 2026. Mothlight turns KQL and SPL into SQL behind the scenes, so you can use whichever one you're used to.

## 1. Scoping the campaign (KQL)

Once we had the five IPs, this told us how much each one did and which ones ran the dropper.

```kql
honeypot
| where ip in ("80.94.92.234", "80.94.92.179", "195.178.110.227", "2.57.122.209", "92.118.39.71")
| summarize Events = count(), Logins = countif(event == "login_success"), Commands = countif(event == "command"), Dropper = countif(command contains "/root/.16") by ip
| sort by Events desc
```

What came back (as of 15:43 UTC):

| ip | Events | Logins | Commands | Dropper |
| --- | --- | --- | --- | --- |
| 195.178.110.227 | 2,624 | 87 | 2,535 | 9 |
| 80.94.92.234 | 392 | 11 | 380 | 0 |
| 2.57.122.209 | 295 | 7 | 287 | 21 |
| 80.94.92.179 | 207 | 5 | 202 | 12 |
| 92.118.39.71 | 207 | 5 | 202 | 12 |

The Dropper column counts command lines, not sessions. Each attempt logs the whole `sudo` chain and then the plain `chmod` it falls back to, so one attempt shows up as a few lines.

## 2. Looking for anyone else using the same toolkit (KQL)

Instead of searching by IP, this one searches for the check script's markers and the payload path. That way it would catch a new IP from the same operator even before it shows up on a blocklist.

```kql
honeypot
| where command contains "_small_control" or command contains "/root/.16"
| summarize Hits = count() by ip
| sort by Hits desc
```

It came back with the same five IPs and nobody else (195.178.110.227: 357 hits, 2.57.122.209: 49, 80.94.92.234: 40, 80.94.92.179: 32, 92.118.39.71: 32). So during this window, the toolkit was only used by this campaign.

## 3. The same hunt in SPL

```spl
index=honeypot (command="*_small_control*" OR command="*/root/.16*")
| stats count by ip
| sort -count
```

## 4. New detection rule: hidden file made executable

The alerts we got were all based on reputation. This rule looks at what the attacker actually does, so it would catch a brand-new IP too.

```kql
honeypot
| where event == "command"
| where command contains "chmod +x" and (command contains "/." or command contains " ./.")
| summarize Attempts = count() by ip
```

On our data it flagged exactly the four dropper IPs (2.57.122.209: 21, 80.94.92.179: 12, 92.118.39.71: 12, 195.178.110.227: 9) and nothing else.

We'd rate this one High, or Critical if it ever fires on a real server instead of the honeypot. Making a dot-file executable right after a fresh SSH login is almost never normal admin work. It maps to ATT&CK T1222.002 and T1564.001.

## 5. New detection rule: password piped into sudo

```kql
honeypot
| where event == "command"
| where command contains "| sudo -S"
| summarize Attempts = count() by ip
```

This matched 18 sessions across the same four IPs, one for each dropper attempt. `sudo -S` reads the password from standard input, so seeing a password echoed into it in a brand-new session is a strong sign of automated privilege escalation (T1548.003).
