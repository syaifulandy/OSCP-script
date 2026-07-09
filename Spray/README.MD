COMPLETE WORKFLOW
START
 │
 ▼
Load Configuration
    • targets.txt
    • users.txt
    • passwords.txt
    • dc_map.txt
    • Active Protocol List
 │
 ▼
FOR EACH TARGET
 │
 ▼
FOR EACH PROTOCOL
 │
 ├─────────────────────────────────────────────────────────────┐
 │                                                             │
 ▼                                                             ▼
SMB                                                           LDAP
 │                                                             │
 │ nxc smb <ip>                                                │ nxc ldap <ip>
 │ -u users                                                    │ -u users
 │ -p passwords                                                │ -p passwords
 │                                                             │
 ▼                                                             ▼
Credential Valid ?                                             Credential Valid ?
 │                                                             │
 ├────► NO                                                     ├────► NO
 │          │                                                  │          │
 │          ▼                                                  │          ▼
 │      Next Protocol                                          │      Next Protocol
 │                                                             │
 ▼                                                             ▼
BEST_LINE (Pwn3d > Valid)                                      BEST_LINE
 │                                                             │
 ▼                                                             ▼
Extract                                                        Extract
DOMAIN                                                         DOMAIN
USER                                                           USER
PASS                                                           PASS
DC_IP                                                          DC_IP
 │                                                             │
 ├────────────────────────────┐                                │
 │                            │                                │
 ▼                            ▼                                ▼
ASREP                     Kerberoast                    ldapdomaindump
 │                            │                                │
 │ GetNPUsers                 │ GetUserSPNs                   │ ldapdomaindump
 │                            │                                │
 ▼                            ▼                                ▼
Hash ?                     Hash ?                      HTML Report
 │                            │
 ├──► NO                     ├──► NO
 │                            │
 ▼                            ▼
Done                        Done
 │                            │
 ▼                            ▼
john                        john
 │                            │
 ▼                            ▼
john --show                 john --show
 │                            │
 ▼                            ▼
final_cracked.txt           final_cracked.txt

 │
 ▼
User Export
 │
 │ nxc smb --users
 │
 ▼
user_export.txt

 │
 ▼
Spider Plus
 │
 │ nxc smb -M spider_plus
 │
 ▼
Loot Files

 │
 ▼
BloodHound
 │
 │ bloodhound-ce-python
 │
 ▼
ZIP Output

 │
 ▼
LSASSY (Only if Pwn3d!)
 │
 │ nxc smb -M lsassy
 │
 ▼
Recovered Credential

Kemudian protocol lain.

WINRM
WINRM

 │
 ▼
nxc winrm <ip>

 │
 ▼
Credential Valid ?

 ├────► NO
 │
 ▼
Next Protocol

 YES
 │
 ▼
Save Credential

 │
 ▼
End

Tidak ada:

Kerberoast
BloodHound
ASREP
MSSQL
MSSQL

 │
 ▼
nxc mssql <ip>

 │
 ▼
Credential Valid ?

 ├────► NO
 │
 ▼
Next Protocol

 YES
 │
 ▼
Save Credential

 │
 ▼
End
SSH
SSH

 │
 ▼
nxc ssh <ip>

 │
 ▼
Credential Valid ?

 ├────► NO
 │
 ▼
Next Protocol

 YES
 │
 ▼
Save Credential

 │
 ▼
End
FTP
FTP

 │
 ▼
nxc ftp <ip>

 │
 ▼
Credential Valid ?

 ├────► NO
 │
 ▼
Next Protocol

 YES
 │
 ▼
Save Credential

 │
 ▼
End
Setelah Semua Target Selesai
wait

 │
 ▼
Merge User Export

 │
 ▼
Build Final Summary

 │
 ▼
Extract Valid Credential

 │
 ▼
FOR EACH VALID CREDENTIAL

 │
 ▼
445 Open ?

 ├────► NO
 │
 ▼
Skip

 YES
 │
 ▼
Already Dumped ?

 ├────► YES
 │
 ▼
Skip

 NO
 │
 ▼
impacket-secretsdump -just-dc

 │
 ▼
Success ?

 ├────► YES
 │
 ▼
Save NTDS

 NO
 │
 ▼
Full secretsdump

 │
 ▼
Save
• SAM
• LSA
• NTDS

 │
 ▼
END
