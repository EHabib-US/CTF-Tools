# CTF Tools Index

A curated, organized index of useful CTF / offensive security tools and references.

---

## Table of Contents
1. [Recon & Scanning](#recon--scanning)  
2. [Network & Traffic Analysis](#network--traffic-analysis)  
3. [Wireless & WiFi](#wireless--wifi)  
4. [Cryptography & Ciphers](#cryptography--ciphers)  
5. [Password Cracking & Wordlists](#password-cracking--wordlists)  
6. [PGP / Keyservers](#pgp--keyservers)  
7. [Forensics & Memory Analysis](#forensics--memory-analysis)  
8. [Steganography & File / Image Analysis](#steganography--file--image-analysis)  
9. [Web App Exploitation & Enumeration](#web-app-exploitation--enumeration)  
10. [Reverse Engineering & Binary Analysis](#reverse-engineering--binary-analysis)  
11. [OSINT & Lookups](#osint--lookups)  
12. [Utilities & Misc](#utilities--misc)  

---

## Recon & Scanning
- **Nmap / Nping** — <https://nmap.org/nping/>  
- **netcat (nc)** — classic TCP/UDP listener/client utility  
- **whois (Kali)** — <https://www.kali.org/tools/whois/>  
- **git-dumper** — dump exposed `.git` repos: <https://github.com/arthaud/git-dumper>  
- **Amazon EC2 AMI Locator** — <https://cloud-images.ubuntu.com/locator/ec2/>

---

## Network & Traffic Analysis
- **Wireshark** — <https://www.wireshark.org/>  
- **Scapy** — Python packet crafting/manipulation: <https://scapy.net/>  
- **Pyshark** — TShark/pcap parsing in Python  
- **NetworkMiner** — <https://www.netresec.com/?page=NetworkMiner>  
- **cap2hashcat** — WPA handshake extraction: <https://hashcat.net/cap2hashcat/>  
- **hcxpcapngtool guide** — <https://dev.to/yegct/hashcat-cracking-pwnagotchi-pcap-files-4fh2>  
- **h264extractor** — RTP H.264/Opus extractor: <https://github.com/volvet/h264extractor>  
- **scrcpy** — Android screen control (ref): <https://github.com/Genymobile/scrcpy>  
- **Understanding Xmas Scans (ref)** — <https://www.plixer.com/blog/understanding-xmas-scans/>

---

## Wireless & WiFi
- **Aircrack-ng** — <https://www.aircrack-ng.org/>  
- **Global WiFi Map** — <https://www.wifimap.io/>  
- **Reaver WPS Cracker (overview)** — <https://outpost24.com/blog/wps-cracking-with-reaver/>

---

## Cryptography & Ciphers
- **CyberChef** — <https://gchq.github.io/CyberChef/>  
- **Cipher Identifier (dCode)** — <https://www.dcode.fr/cipher-identifier>  
- **Boxentriq code-breaking tools** — <https://www.boxentriq.com/>  
- **Cryptii (e.g., Caesar)** — <https://cryptii.com/pipes/caesar-cipher>  
- **Autokey cipher (explanation)** — <https://crypto.interactive-maths.com/autokey-cipher.html>  
- **Hash length extension** — <https://github.com/iagox86/hash_extender>  
- **Bruteforce Salted OpenSSL** — <https://github.com/glv2/bruteforce-salted-openssl>  
- **Kullback test (Vigenère analysis)** — <https://corgi.rip/blog/kullback-in-ctf/>  
- **DTMF decoders** — Web: <https://unframework.github.io/dtmf-detect/> • CLI: <https://github.com/ribt/dtmf-decoder> • Audacity plugin: <https://forum.audacityteam.org/t/dtmf-decoder-plugin/34210/4>

---

## Password Cracking & Wordlists
- **Hashcat** — <https://hashcat.net/hashcat/>  
- **John the Ripper** — <https://www.openwall.com/john/>  
- **PDF → JtR (how-to)** — <https://ourcodeworld.com/articles/read/939/how-to-crack-a-pdf-password-with-brute-force-using-john-the-ripper-in-kali-linux>  
- **CrackStation** — <https://crackstation.net/>  
- **Ophcrack** — <https://ophcrack.sourceforge.io/>  
- **AP-less WPA2-PSK lab** — <https://www.attackdefense.com/challengedetailsnoauth?cid=1257>  
- **pwcrack-builder** — <https://github.com/quasar098/pwcrack-builder>  
- **SecLists** — repo of wordlists/payloads: <https://github.com/danielmiessler/SecLists>  
  - Specific list: US cities — <https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/us-cities.txt>  
- **OneRuleToRuleThemAll (hashcat rules)** — <https://github.com/NotSoSecure/password_cracking_rules>  
- **OneRuleToRuleThemStill (updated)** — <https://github.com/stealthsploit/OneRuleToRuleThemStill>  
- **Pentest Everything: lists & rules** — <https://viperone.gitbook.io/pentest-everything/resources/hashcat-word-lists-and-rules>  
- **Bulbapedia (Pokémon names list)** — useful themed wordlist: <https://bulbapedia.bulbagarden.net/wiki/List_of_Japanese_Pokémon_names>  
- **OSM Names downloads** — <https://osmnames.org/download/>

---

## PGP / Keyservers
- **MIT PGP Keyserver** — <https://pgp.mit.edu/>  
- **Ubuntu Keyserver** — <https://keyserver.ubuntu.com/>  
- **Entrust CT Search UI** — <https://ui.ctsearch.entrust.com/ui/ctsearchui>  
- **Online PGP (OpenPGP.js)** — <https://webencrypt.org/openpgpjs/>  
- **Kleopatra (Windows GUI)** — <https://www.openpgp.org/software/kleopatra/>  
- **ccrypt on Linux (how-to)** — <https://www.geeksforgeeks.org/encrypt-decrypt-files-in-linux-using-ccrypt/>

---

## Forensics & Memory Analysis
- **FTK Imager** — <https://www.exterro.com/ftk-product-downloads/ftk-imager-version-4-7-1>  
- **Volatility Workbench** — <https://www.osforensics.com/tools/volatility-workbench.html>  
- **Mimikatz (reference)** — <https://github.com/ParrotSec/mimikatz>  
- **pypykatz** — <https://github.com/skelsec/pypykatz>  
- **Dumping LSASS without Mimikatz (ref)** — <https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsass-passwords-without-mimikatz-minidumpwritedump-av-signature-bypass>  
- **Chainsaw** — <https://github.com/WithSecureLabs/chainsaw>  
- **EvtxECmd (Windows EVTX parser)** — <https://github.com/EricZimmerman/evtx>  
- **Registry Explorer (SANS)** — <https://www.sans.org/tools/registry-explorer/>  
- **Autopsy** — <https://www.autopsy.com/download/>  
- **analyzeMFT** — <https://github.com/dkovar/analyzeMFT>  
- **Help Net: 5 free DFIR tools (ref)** — <https://www.helpnetsecurity.com/2024/02/15/free-digital-forensics-tools/>  
- **REMnux (malware analysis distro)** — <https://remnux.org/>

---

## Steganography & File / Image Analysis
- **Exif viewer** — <https://exif.tools/>  
- **Aperi’Solve (image analyzer)** — <https://www.aperisolve.com/>  
- **Binwalk** — <https://www.kali.org/tools/binwalk/>  
- **Steghide** — <https://www.kali.org/tools/steghide/>  
- **Unicode/Homoglyph stego** — <https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder>  
- **PNG repair** — <https://compress-or-die.com/repair>  
- **.DS_Store parser** — <https://github.com/hanwenzhu/.DS_Store-parser>  
- **Hex editors** — HxD: <https://mh-nexus.de/en/hxd/> • ImHex: <https://github.com/WerWolv/ImHex>  
- **Unredacter / depixeler** — <https://github.com/BishopFox/unredacter>  
- **File signatures / magic bytes** —  
  - Wikipedia: <https://en.wikipedia.org/wiki/List_of_file_signatures>  
  - NetSPI guide: <https://www.netspi.com/blog/technical/web-application-penetration-testing/magic-bytes-identifying-common-file-formats-at-a-glance/>

---

## Web App Exploitation & Enumeration
- **Burp Suite** — <https://portswigger.net/burp>  
- **OWASP ZAP** — <https://www.zaproxy.org/>  
- **Wappalyzer (extension)** —  
  - Chrome: <https://chromewebstore.google.com/detail/wappalyzer-technology-pro/gppongmhjkpfnbhagpmjfkannfbllamg>  
  - Firefox: <https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/>  
- **DirBuster (Kali)** — <https://www.kali.org/tools/dirbuster/>  
- **curl (Kali)** — <https://www.kali.org/tools/curl/>  
- **JavaScript deobfuscators** —  
  - de4js: <https://lelinhtinh.github.io/de4js/>  
  - deobfuscate.io: <https://deobfuscate.io/>  
  - JSFuck decoder: <https://www.53lu.com/tool/jsfuckdecode/> • JSFuck: <https://jsfuck.com/>  
- **HackerGPT (AI assistant)** — <https://chat.hackerai.co/>  

---

## Reverse Engineering & Binary Analysis
- **GDB** — <https://sourceware.org/gdb/>  
- **GEF (GDB Enhanced Features)** — <https://github.com/hugsy/gef>  
- **Ghidra** — <https://ghidra-sre.org/>  
- **IDA Free** — <https://hex-rays.com/ida-free/#download>  
- **Binary Ninja** — <https://binary.ninja/>  
- **ReverserAI (Binary Ninja plugin)** — <https://github.com/mrphrazer/reverser_ai>  
- **Android emulators guide (RE)** — <https://github.com/LaurieWired/android_emulators_for_reverse_engineers>

---

## OSINT & Lookups
- **OSINT.lol — Database Lookup** — <https://osint.lolarchiver.com/database_lookup>  
- **MAC Address / Vendor Lookup (Cisco page)** — <https://www.adminsub.net/mac-address-finder/cisco>  
- **GPS Coordinates** — <https://gps-coordinates.net/>

---

## Utilities & Misc
- **MongoDB Compass** — <https://www.mongodb.com/products/tools/compass>  
- **Redis — Tools & GUIs** — <https://redis.io/resources/tools/>  
- **CT Search (Entrust)** — <https://ui.ctsearch.entrust.com/ui/ctsearchui>  
- **Sudoku code (crypto scheme write-up)** — <https://dellsystem.me/posts/sudoku-code>  
- **HackTricks (stego section)** — <https://book.hacktricks.xyz/crypto-and-stego/stego-tricks>  
- **NoSQL injection (HackTricks)** — <https://book.hacktricks.xyz/pentesting-web/nosql-injection>

---

### Notes
Use these tools only within authorized scopes (CTFs, labs, or engagements with explicit permission). Verify checksums when downloading binaries and prefer building from source where practical.
