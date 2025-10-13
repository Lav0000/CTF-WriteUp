# **RedLine Lab**
Employ Volatility to analyze a memory dump, identifying suspicious processes, network IOCs, memory protections, and attacker's command-and-control infrastructure.

Category: `Endpoint` `Forensics`
Tactics: `Privilege Escalation` `Defense Evasion` `Command and Control`
Tools: `Volatility` `Findstr` `HxD`

Links: https://cyberdefenders.org/blueteam-ctf-challenges/redline/

---

### 🧩 Bước 1 — Liệt kê các tiến trình (psscan)
```powershell
vol -f .\MemoryDump.mem windows.psscan.PsScan
````

`psscan` quét khối memory kernel để tìm `EPROCESS` (kể cả tiến trình bị ẩn hoặc đã terminate).

Output:

```
#mal 5896    8844    oneetx.exe      0xad8189b41080  5   -   1   True    2023-05-21 22:30:56.000000 UTC  N/A     Disabled
#VPN 4628    6724    tun2socks.exe   0xad818de82340  0       -       1       True    2023-05-21 22:40:10.000000 UTC  2023-05-21 23:01:24.000000 UTC  Disabled

```

---

### 🧩 Bước 2 — Xác định child của tiến trình (pstree)

```powershell
vol -f .\MemoryDump.mem windows.pstree.PsTree --pid 5896
```

`pstree` hiển thị quan hệ cha–con giữa các process, giúp xác định tiến trình bị spawn bởi mã độc.

Output:

```
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime        Audit   Cmd     Path

5896    8844    oneetx.exe      0xad8189b41080  5       -       1       True    2023-05-21 22:30:56.000000 UTC  N/A     \Device\HarddiskVolume3\Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe   -       -
* 7732  5896    rundll32.exe    0xad818d1912c0  1       -       1       True    2023-05-21 22:31:53.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\SysWOW64\rundll32.exe   -       -
```

---

### 🧩 Bước 3 — Kiểm tra vùng nhớ khả nghi (malfind)

```powershell
vol -f .\MemoryDump.mem windows.malfind.Malfind --pid 5896
```

`malfind` dò các vùng VAD có quyền thực thi và chứa dấu hiệu PE (`MZ header`) — thường là payload được nạp trực tiếp vào RAM.

Output (PID 5896):

```
PID     Process Start VPN       End VPN Tag     Protection      CommitCharge    PrivateMemory   File output     Notes   Hexdump Disasm

5896    oneetx.exe      0x400000        0x437fff        VadS    PAGE_EXECUTE_READWRITE  56      1       Disabled        MZ header
```

Vùng nhớ này có quyền **PAGE_EXECUTE_READWRITE** và chứa header `MZ` → dấu hiệu giải nén hoặc reflective load trong memory.

---

### 🧩 Bước 4 — Tìm tiến trình VPN (Outline / tun2socks)

```powershell
vol -f .\MemoryDump.mem windows.pstree.PsTree --pid 4628
```

Output:

```
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime        Audit   Cmd     Path

588     520     winlogon.exe    0xad8186f450c0  5       -       1       False   2023-05-21 22:27:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\winlogon.exe   -       -
* 3556  588     userinit.exe    0xad818c02f340  0       -       1       False   2023-05-21 22:30:28.000000 UTC  2023-05-21 22:30:43.000000 UTC  \Device\HarddiskVolume3\Windows\System32\userinit.exe   -       -
** 3580 3556    explorer.exe    0xad818c047340  76      -       1       False   2023-05-21 22:30:28.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\explorer.exe    C:\Windows\Explorer.EXE C:\Windows\Explorer.EXE
*** 6724        3580    Outline.exe     0xad818e578080  0       -       1       True    2023-05-21 22:36:09.000000 UTC  2023-05-21 23:01:24.000000 UTC  \Device\HarddiskVolume3\Program Files (x86)\Outline\Outline.exe -      -
**** 4628       6724    tun2socks.exe   0xad818de82340  0       -       1       True    2023-05-21 22:40:10.000000 UTC  2023-05-21 23:01:24.000000 UTC  \Device\HarddiskVolume3\Program Files (x86)\Outline\resources\app.asar.unpacked\third_party\outline-go-tun2socks\win32\tun2socks.exe   -       -
```

`Outline.exe` là client, `tun2socks.exe` là helper tạo TUN để redirect TCP → SOCKS (VPN activity).

---

### 🧩 Bước 5 — Tìm kết nối mạng của oneetx.exe (netscan)

```powershell
vol -f .\MemoryDump.mem windows.netscan.NetScan
```

`netscan` liệt kê các TCP connection trong kernel memory, mapping đến PID tương ứng. Sau đó search strings oneetx.exe

Output:

```
0xad818de4aa20  TCPv4   10.0.85.2       55462   77.91.124.20    80      CLOSED  5896    oneetx.exe      2023-05-21 23:01:22.000000 UTC

```

Outbound từ `oneetx.exe` → **77.91.124.20:80** (attacker host).

---

### 🧩 Bước 6 — Tìm full URL `.php` request trong memory
Vì HTTP request plaintext (port 80) thường để lại chuỗi URL trong memory.
Ta dùng HxD search strings `http://` hoặc `.php`


Output:

```
http://77.91.124.20/store/games/index.php
```

Full URL cho thấy endpoint PHP được malware truy cập.

---

### 🧩 Bước 7 — Tìm đường dẫn đầy đủ của file thực thi

dùng HxD search strings `oneetx.exe` hoặc chạy lệnh pstree
```
vol -f .\MemoryDump.mem windows.pstree.PsTree --pid 5896
```

Output:

```
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime        Audit   Cmd     Path

5896    8844    oneetx.exe      0xad8189b41080  5       -       1       True    2023-05-21 22:30:56.000000 UTC  N/A     \Device\HarddiskVolume3\Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe   -       -
```

Đường dẫn gốc của file `C:\Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe` thực thi trên đĩa — thường thấy ở temp folder của user.

---

### ✅ Tổng hợp kết quả

| Câu hỏi            | Đáp án                                                     |
| ------------------ | ---------------------------------------------------------- |
| Suspicious process | `oneetx.exe`                                               |
| Child process      | `rundll32.exe`                                             |
| Memory protection  | `PAGE_EXECUTE_READWRITE`                                   |
| VPN process        | `Outline.exe`                                              |
| Attacker IP        | `77.91.124.20`                                             |
| Full URL (.php)    | `http://77.91.124.20/store/games/index.php`                |
| Full file path     | `C:\Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe` |

```
```
