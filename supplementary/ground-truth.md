# Annotated ground truth

The following listing shows the correspondence between the provided
`tasks.json` file and the original ground truth document.  For each line in the
original document, we indicate the ID of the raw events identified by the
security analyst, if any.

```
# Day 1 - "Plain PowerShell Empire"

Sysclient0201 VL8B5T3U 142.20.56.202 5452
    43fb9623-3cd1-45ec-ab22-dbe46e75240e

Sysclient0201 LUAVR71T 142.20.56.202 2952
    55afc144-b943-4211-8ac1-2e7b75de69e0

Sysclient0402 NEK5H8GX 142.20.57.147 3168
    7db901fd-e1bf-4c38-9833-b4d0cba08633

Sysclient0660 DS29HY41 142.20.58.149 880
    97c516eb-9a25-4512-8c6d-9759bb747b74

SYSCLIENT0104 K9SW73AF 142.20.56.105 3160
    f3815ab9-206c-4072-8a50-46a1d62e10f6

SYSCLIENT0205 MX9LTPSF 142.20.56.206 5012
    13ae9c93-f636-4d3e-9c74-63d79af1e428

SYSCLIENT0321 AC5BVNRP 142.20.57.66 2980
    545069e6-8c99-43c8-9a18-9bdb9d33584c

SYSCLIENT0255 HR3PK2ZF 142.20.57.0 3472
    61c961ae-bd19-49f0-a7d7-2f3551339a55

SYSCLIENT0355 A83TU4KL 142.20.57.100 1884
    f3986ce9-5921-43e4-abc3-a49b069db040

SYSCLIENT0503 872METCN 142.20.57.248 1472
    bea73615-2519-4802-9958-98f50ab8eef1

SYSCLIENT0462 FNP6XK89 142.20.57.207 2536
    e15537fe-fdb0-49d4-a1fd-de34e8215617

SYSCLIENT0559 ANP2E69T 142.20.58.48 1400
    1c46f2f7-132e-4b3b-9bdb-cea1140db1fc

SYSCLIENT0419 XS3AWFB9 142.20.57.164 1700
    9decc021-64b4-4e72-93d3-9c5a2f617837

SYSCLIENT0609 325T9FEN 142.20.58.98 3460
    e8cd79b8-6d34-4e34-8771-535c38cc5178

SYSCLIENT0771 75HYXEL3 142.20.59.4 4244
    86bbfaf7-855b-4eac-bf26-ddb1aca83ca2

SYSCLIENT0955 98GKNAFX 142.20.59.188 4760
    0c3eed6b-da4c-44a4-9057-590ab3de0d9f

SYSCLIENT0874 LZFHNCES 142.20.59.107 5224
    ecbc8959-5d6c-45f0-b166-9efeb772a0cb

SYSCLIENT0170 UD9R6S7T 142.20.56.171 644
    45ea6896-5423-468e-abbf-00d109a009ce

DC1 XH32VTK5 142.20.61.130 1852
    Dataset does not include logs from DC1.

09/23/19 11:23:29 -- Manually accessed console on Sysclient0201 and navigated to news.com:8000 to download runme.bat, a malicous Powershell empire stager
    7d6dabac-1c18-48ab-a973-da8b2d170da9

09/23/19 11:24:19 -- Sysclient0201, closed firefox tab and deleted runme.bat
    3d4bdefb-c63c-4df6-af64-564ba52c6b61

09/23/19 11:24:54 -- Successfull checkin for Agent VL8B5T3U on Sysclient0201 ip 142.20.56.202
    5c6552fe-e6a6-43f6-9af2-3fb8a43b3a65

09/23/19 11:26:02 -- On Sysclient0201 agent VL8B5T3U, Used PowershellEmpire Module Bypasses UAC, which performs a registry modification of the \"windir\" value in \"Environment\" to bypass UAC.
    5cedea14-aed8-4ca4-98e8-642c816ed754

09/23/19 11:26:38 -- On sysclient0201, successful checkin of elevated agent LUAVR71T
    55afc144-b943-4211-8ac1-2e7b75de69e0

09/23/19 11:26:56 -- On Sysclient0201, killing agent VL8B5T3U
    ecfc59ec-3e42-4531-a250-7af2f94b60c1

09/23/19 11:33:14 -- On Sysclient0201 agent LUAVR71T, ran mimikatz to collect clear text passwords in memory
    cd005a16-9176-4fb9-853d-38ac429147d6

09/23/19 11:35:26 -- On Sysclient0201 agent LUAVR71T, obtained password for user systemia.com\\zleazer via mimikatz
    The raw event corresponding to this line was not discovered.

09/23/19 11:37:15 -- On Sysclient0201 agent LUAVR71T, used psinject to inject into the LSASS process
    9cc75983-4433-4ef1-b734-5a48a2346b39

09/23/19 11:38:09 -- On Sysclient0201 agent LUAVR71T, Process injection seems to have failed.
    The raw event corresponding to this line was not discovered.

09/23/19 11:39:25 -- On Sysclient0201 agent LUAVR71T, established persistence by modifying HKCU:Software\\Microsoft\\Windows\\CurrentVersion\\Debug registry entry
    3ee3e6e9-0601-46a4-90fa-f823c68b463c

09/23/19 11:40:41 -- On Sysclient0201 agent LUAVR71T, obtained process listing by running ps through powershell
    944a93d0-0c7c-4590-b48e-d081d36269b9

09/23/19 11:41:50 -- On Sysclient0201 agent LUAVR71T, retried psinject into lsass
    b0331e2c-2285-45fb-9644-a443700edd02

09/23/19 12:51:59 -- On Sysclient0201 agent LUAVR71T, collected data collection by obtaining a screenshot of the desktop.
    989d6566-697b-4025-aca5-5ad344c1ef96

09/23/19 12:58:20 -- On Sysclient0201 agent LUAVR71T, conducted ARP scan on /22 of 142.20.56.202
    2e617f24-d5cd-45f2-8130-73673c7073b6

09/23/19 13:07:11 -- On Sysclient0201 agent LUAVR71T, ARP scan failed. Attempting to use SMB on 142.20.56.204 with credentials from Sysclient0201
    416f0e20-de02-4f63-97d7-928399722e5b

09/23/19 13:08:28 -- On Sysclient0201 agent LUAVR71T, re-attempted ARP scan without setting any values.
    9125f70e-c7d2-46fe-b04b-1e6cb1bc7d49

09/23/19 13:15:48 -- On Sysclient0201 agent LUAVR71T, executed ping sweep against 142.20.56.0/24
    f7cfcf76-a672-47cd-8063-8ebc4f8f7f4d

09/23/19 13:24:36 -- On Sysclient0201 agent LUAVR71T, pivoted to Sysclient0402 using invoke_wmi
    9bcea60a-d719-499e-aac1-710860b10ca1

09/23/19 13:25:41 -- On sysclient0402 agent NEK5H8GX checked in as an elevated agent
    7db901fd-e1bf-4c38-9833-b4d0cba08633

09/23/19 13:29:47 -- On Sysclient0402 agent NEK5H8GX, imported and ran ping sweep script to run against 142.20.57.0/24
    dd40d075-34a2-4952-b9ac-1f5371471147

09/23/19 13:35:22 -- On Sysclient0402 agent NEK5H8GX, pivoted to Sysclient0660 using invoke_wmi.
    5ccaaf57-4fe2-4e70-85b0-5514deb4d6f8

09/23/19 13:35:22 -- Agent DS29HY41 checks in.
    97c516eb-9a25-4512-8c6d-9759bb747b74

09/23/19 13:38:31 -- On Sysclient0660 agent DS29HY41, used ipconfig to obtain IP
    473094ab-a7ff-4887-b5d0-6533167541c8

09/23/19 13:40:38 -- On Sysclient0660 agent DS29HY41, used mimikatz to obtain cleartext passwords from memory
    1b2e5557-e08e-41af-8afe-735d26be0e70

09/23/19 13:44:23 -- On Sysclient0660 agent DS29HY41, attempted to migrate to local user process with psinject. Failed to inject.
    94d655d1-7530-4c31-b2fc-4ef6488f72ac

09/23/19 13:49:00 -- On Sysclient0660 agent DS29HY41, obtained list of processes with ps
    0bd082a7-409a-48a7-9dd7-eb91048ad6ef

09/23/19 13:50:56 -- On Sysclient0660 agent DS29HY41, attempted to inject shellcode into process 4480. Injection failed.
    d0f99cdd-9506-4fba-aef8-259d37181db8

09/23/19 13:54:11 -- On Sysclient0660 agent DS29HY41, executed script to return domain controller information.
    0a29dac9-7117-4e11-ab3c-ea57966b5888

09/23/19 13:56:48 -- On Sysclient0660 agent DS29HY41, imported and ran powershell script to find domain controllers
    2f6bae0e-d05f-4cd0-8421-adcdf28874a9

09/23/19 14:02:12 -- On Sysclient0660 agent DS29HY41, downloaded file zipfldr.dll
    266d9d07-0be5-42d3-a288-7c6eca87aa45

09/23/19 14:04:45 -- On Sysclient0660 agent DS29HY41, used invoke_wmi to pivto to domain controller 1. XH32VTK5 checks in on ip 142.20.58.149
    Dataset does not include logs from DC1.

09/23/19 14:06:01 -- Killed agents Sysclient0201 LUAVR71T, Sysclient0402 NEK5H8GX and Sysclient0660 DS29HY41
    ecd3188c-9067-4529-90eb-8d91aba972b8

09/23/19 14:06:01 -- Killed agents Sysclient0201 LUAVR71T, Sysclient0402 NEK5H8GX and Sysclient0660 DS29HY41
    3e327270-d70c-41c6-ba2e-a2e11a04a2a2

09/23/19 14:06:01 -- Killed agents Sysclient0201 LUAVR71T, Sysclient0402 NEK5H8GX and Sysclient0660 DS29HY41
    75cf5bc8-2bc0-4a68-bd69-5dadd3906a94

09/23/19 14:07:21 -- On DC1 agent XH32VTK5, ran mimikatz
    Dataset does not include logs from DC1.

09/23/19 14:09:21 -- On DC1 agent XH32VTK5, gathered user hdorka's hashes using mimikatz's lsadump capability
    Dataset does not include logs from DC1.

09/23/19 14:45:13 -- On DC1 agent XH32VTK5, used Invoke_wmi to spread to: SYSCLIENT0104,SYSCLIENT0170,SYSCLIENT0205,SYSCLIENT0255,SYSCLIENT0321,SYSCLIENT0355,SYSCLIENT0419,SYSCLIENT0462 ,SYSCLIENT0503,SYSCLIENT0559,SYSCLIENT0609,SYSCLIENT0771,SYSCLIENT0874,SYSCLIENT0955
    Dataset does not include logs from DC1.

09/23/19 15:24:33 -- On DC1 agent XH32VTK5, kill agents on: SYSCLIENT0104,SYSCLIENT0170,SYSCLIENT0205,SYSCLIENT0255,SYSCLIENT0321,SYSCLIENT0355,SYSCLIENT0419,SYSCLIENT0462 ,SYSCLIENT0503,SYSCLIENT0559,SYSCLIENT0609,SYSCLIENT0771,SYSCLIENT0874,SYSCLIENT0955
    Dataset does not include logs from DC1.

09/23/19 15:30:00 -- On Sysclient0201, removed registry persistence at HKCU:Software\\Microsoft\\Windows\\CurrentVersion\\Debug
    515e06a3-8cc1-401c-b22d-f77224958279


# Day 2 - "Custom Powershell Empire"

Sysclient0501 4BW2MKUF 142.20.57.246 648
    60bf9b6b-b673-43e5-9ed8-05453e50467a

Sysclient0501 9HUGDCRL 142.20.57.246 5076
    ad9600b0-d610-4b7a-b982-cc76a0150cfa

Sysclient0501 6H8SZPCW 142.20.57.246 1748
    72f0c069-24f2-4f47-8dc9-971e399b75f0

Sysclient0811 DS8V3RNH 142.20.59.44 3780
    a44db665-e61f-487f-a5e6-ff9993e70739

DC1.systemia.com VUBW3KYE 142.20.61.130 3880
    Dataset does not include logs from DC1.

Sysclient0010 6FEZ8L4N 142.20.56.11 3584
    bd5de983-428f-474e-8884-b7d06aff41d7

Sysclient0069 EMK3VW7F 142.20.56.70 4152
    75f5ebc2-dd6e-4cbc-b9af-8ba90118aedc

Sysclient0203 UXCSTKZ9 142.20.56.204 5388
    c89bf1da-7ede-4600-bf17-4c1d035c65d6

Sysclient0358 PE54DBYX 142.20.57.103 2984
    8249ab1f-09f9-4db3-82bb-6c28d336ac02

Sysclient0618 73FCWS1G 142.20.58.107 4060
    856426f4-876d-43d8-862e-ae2c02c9afd4

Sysclient0851 5BUEZALX 142.20.59.84 4652
    4ffdcfcb-965f-4c69-b8b5-197ac81e349e

09/24/19 10:28:56 -- Sent email with malicious word document to bantonio@systemia.com on Sysclient0501 and rsantilli@systemia.com on Sysclient0811 from sgerard@ameblo.jp
    73a1f1a6-086b-4115-ba9e-ecdbbf99beb2

09/24/19 10:36:51 -- On Sysclient0501, opened malicious attachemnt named payroll.docx. Agent K3G1U8DN checks in.
    8acf2c27-cd2d-4cf1-a064-270bb423c8d7

09/24/19 10:40:14 -- On Sysclient0811, opened malicious attachment named payroll.docx. Agent DS8V3RNH checks in.
    a2bd41b8-2f06-4548-8686-e7e53f9db19f

09/24/19 10:46:02 -- On Sysclient0501 agent K3G1U8DN, injected powershell script to pivot to PowerShell Empire on sports.com 202.6.172.98 port 443
    58677aed-426c-4b12-bc99-aa4a858797ae

09/24/19 10:46:02 -- Agent 4BW2MKUF checks in.
    60bf9b6b-b673-43e5-9ed8-05453e50467a

09/24/19 10:51:49 -- Killed agent K3G1U8DN on Sysclient0501
    0863d251-fcfa-4e98-ac31-3c6826c5323b

09/24/19 11:03:36 -- Started DeathStar to auto find and obtain access to domain controller
    dd026e9c-0d88-415b-b146-04471c1706ab

09/24/19 11:04:12 -- Deathstar via Sysclient0501 agent 4BW2MKUF, obtains domain SID
    637fabd7-2be1-4cd2-a33d-a851fe6f6277

09/24/19 11:04:35 -- Deathstar via Sysclient0501 agent 4BW2MKUF, obtains list of 43 Domain Admins
    0fa4352d-2bed-4ed0-a06e-4daff59b2464

09/24/19 11:05:39 -- Deathstar via Sysclient0501 agent 4BW2MKUF, queried to find domain controllers
    71b0e667-f9a7-4ba3-aeee-54ec96e9d30f

09/24/19 11:09:08 -- Deathstar via Sysclient0501 agent 4BW2MKUF, started lateral movement
    0758fafd-7dc4-4bdb-92cc-60482603e3f9

09/24/19 11:09:22 -- Deathstar via Sysclient0501 agent 4BW2MKUF, started domain privesc
    acc1dccf-3f3c-4cf6-8852-c27f6f5e7a26

09/24/19 11:09:44 -- Deathstar via Sysclient0501 agent 4BW2MKUF, attempting to elevate using bypassuac_eventvwr
    24220a6b-9129-43d3-944e-8b56143fbc0a

09/24/19 11:10:32 -- Deathstar via Sysclient0501 agent 4BW2MKUF, searched for GPOs containing credentials using GPP SYSVOL privesc
    49530707-6416-4ff3-a911-3bdca783c24a

09/24/19 11:13:32 -- Deathstar via Sysclient0501 agent 4BW2MKUF, discovered current security context has admint o 1025 hosts.
    The raw event corresponding to this line was not discovered.

09/24/19 11:20:19 -- On Sysclient0501 agent 4BW2MKUF, obtained elevated agent on domain controller. Agent VUBW3KYE on DC1.systemia.com checks in.
    2921030d-898d-4184-905d-a3f8333fbede

09/24/19 11:23:27 -- On Sysclient0501 agent 4BW2MKUF, attempted to bypassed UAC with module privesc/bypassuac_env which modifies registry entry of windir value in environment
    fab35a85-bebf-4f5c-a58b-7a0c370c1eb8

09/24/19 11:23:45 -- On Sysclient0501 agent 4BW2MKUF, privesc failed.
    The raw event corresponding to this line was not discovered.

09/24/19 11:25:06 -- On Sysclient0501 agent 4BW2MKUF, attempted bypassuac with privesc/bypassuac_fodhelper. Failed.
    65c5b5c1-a49e-447a-80a8-70ecc34814eb

09/24/19 11:26:34 -- On Sysclient0501 agent 4BW2MKUF, used invoke wmi on localhost to obtain elevated Agent. Failed to elevated, normal agent 9HUGDCRL checked in.
    ad9600b0-d610-4b7a-b982-cc76a0150cfa

09/24/19 11:31:17 -- On DC1.systemia.com agent VUBW3KYE, attempted to pivot to obtain elevated agent using WMI. Got access denied for Sysclient0501 and 0502
    Dataset does not include logs from DC1.

09/24/19 11:33:15 -- On DC1.systemia.com agent VUBW3KYE, pivoted to Sysclient0501 with an elevated agent by usign administrator credentials. Agent 6H8SZPCW checks in.
    72f0c069-24f2-4f47-8dc9-971e399b75f0

09/24/19 11:34:56 -- On Sysclient0501 agent 6H8SZPCW, set persistence using WMI subscription. Set to reach back at 10:00 everyday or within 5 minutes of boot.
    7af7404b-1627-46cc-9bda-cc2ac592b153

09/24/19 11:35:53 -- Killed agents Sysclient0501 4BW2MKUF and Sysclient0501 9HUGDCRL
    df13880b-6879-4639-a137-55289c833b16

09/24/19 11:35:53 -- Killed agents Sysclient0501 4BW2MKUF and Sysclient0501 9HUGDCRL
    b42dd33d-5a63-4fd4-aa9d-79b42cc6c7b4

09/24/19 11:37:35 -- On Sysclient0501 agent 6H8SZPCW, used findtrusteddocuments to enumerate registry to determine any trusted documents and trusted locations.
    c359ccad-b6be-4c00-80cf-38b95b3b5b1a

09/24/19 11:39:38 -- On Sysclient0501 agent 6H8SZPCW, used winenum script with keywords \"important,secret,classified\" to search files and obtain host information
    The raw event corresponding to this line was not discovered.

09/24/19 11:41:53 -- On Sysclient0501 agent 6H8SZPCW, ran script to check for windows privesc vectors.
    3d25d832-4e41-464d-85f1-a71aed0e7b8e

09/24/19 11:45:13 -- On Sysclient0501 agent 6H8SZPCW, uploaded plink.exe
    8aa13498-f515-4d8d-bec7-a97ea2928de1

09/24/19 13:05:03 -- On Sysclient0501 agent 6H8SZPCW, validated upload worked with ls command
    The raw event corresponding to this line was not discovered.

09/24/19 13:11:23 -- On Sysclient0501 agent 6H8SZPCW, started reverse ssh connection to port forward RDP port to attacker system. Lost contact with agent 6H8SZPCW.
    d1048c30-a0f3-4afa-95d8-3d5e33cdeac9

09/24/19 13:19:38 -- On Sysclient0501, connected via RDP to host via forwarded port using sysadmin account.
    772a282b-f02e-4e07-a0df-87a83ecbe8c7

09/24/19 13:25:46 -- Agent DS8V3RNH lost contact.
    b127a987-df7d-4ac9-bc98-cfa806381d30

09/24/19 13:26:57 -- On Sysclient0501 via RDP session, downloaded fileTransfer1000.exe (nc.exe) from news.com:8080 via chrome.
    5eb73938-c1ed-45e3-8aa7-c9765293e021

09/24/19 13:31:29 -- On Sysclient0501 via RDP session, compressed documents in C:\\documents for exfiltration.
    39f3e41d-e502-49c0-9c29-bc88249ed697

09/24/19 13:44:34 -- On Sysclient0501 via RDP session, exfiltrated export.zip to news.com port 9999 using fileTransfer1000.exe (nc.exe)
    a1f31ea0-e50c-4ddb-8aac-9317914bd27a

09/24/19 13:45:12 -- On Sysclient0501 via RDP session, cleaned up fileTransfer1000.exe and export.zip
    The raw event corresponding to this line was not discovered.

09/24/19 13:46:58 -- On Sysclient0501 via RDP session, RDPed to Sysclient0974
    5f2d9391-0197-4eec-a4a0-935199460bdb

09/24/19 13:51:45 -- On Sysclient0974 via RDP session, browsed files in C:\\documents
    e799248a-d608-41ef-9d05-4dee8cc0bd4d

09/24/19 13:54:43 -- On Sysclient0974 via RDP session, RDPed to Sysclient0005
    d8228250-6b15-4a05-8b37-505f8947ee08

09/24/19 14:06:06 -- On Sysclient0005 via RDP session, mounted network share \\\\142.20.61.135\\share
    871e4e5c-593c-4b08-93ca-2c419abf7e0e

09/24/19 14:34:31 -- On Sysclient0005 via RDP session, added majority of share drive files to compressed folder name allgone.zip and moved to user Download folder.
    2bd805a1-e2f9-4e74-ae91-56e07466b474

09/24/19 14:37:02 -- On Sysclient0005 via RDP session, navigated to news.com:4445 and downloaded movingonup.exe (nc.exe)
    49e40571-9f30-42c0-a09d-86fbb82ba69e

09/24/19 15:04:14 -- On Sysclient0005 via RDP session, exported 3.5 gb exfil file allgona.zip
    ff4f8d75-fcc7-452a-9bd9-f64695bbce5f

09/24/19 15:22:48 -- On Sysclient0005 via RDP session, cleaned up files in downloads folder
    e2217520-4884-493e-b1be-f4a654efe646

09/24/19 15:23:26 -- On Sysclient0005 closed RDP session.
    22dce772-6896-44ba-8f54-7284e15fe89b

09/24/19 15:27:32 -- On Sysclient0974 closed RDP session.
    72e41f98-8436-4737-8647-af59f18af84f

09/24/19 15:28:36 -- On Sysclient0501 closed RDP session.
    36ed92da-62c7-4d48-8fbd-42536786046d

09/24/19 15:42:36 -- On DC1.systemia.com agent VUBW3KYE, used invoke_wmi to spread to Sysclient0010,Sysclient0069,Sysclient0203,Sysclient0358,Sysclient0618,Sysclient0851
    Dataset does not include logs from DC1.

09/25/19 09:00:00 -- Agents ran overnight on: DC1.systemia.com VUBW3KYE, Sysclient0010 6FEZ8L4N, Sysclient0069 EMK3VW7F, Sysclient0203 UXCSTKZ9, Sysclient0358 PE54DBYX, Sysclient0618 73FCWS1G, Sysclient0851 5BUEZALX
    The raw event corresponding to this line was not discovered.

09/25/19 10:00:00 -- Sysclinet0501 WMI Subcription persistence method activates, agent XVGHS45M checks in.
    485a8f21-3f75-4fa3-9333-9c0f847056e1

Meterpreter process on Sysclient0051 PID 2712 cKfGW.exe Migrated to lsass
    5ceee15b-fe47-4d5f-8380-473107941e93

Meterpreter process on Sysclient0351 PID 1932 f.exe migrated to lwabeats
    32e162c7-0ac5-403f-a7b4-a0b98964258f


# Day 3 - "Malicious Upgrade"

09/25/19 10:29:42 -- On Sysclient0051, updated notepad++ which download malicious binary \"update.exe\" which is a meterpreter payload.
    75127b7a-300e-48c1-9695-9f360d654590

09/25/19 10:31:08 -- On Sysclient0051, obtained system via meterpreters get system module.
    abcd8499-e399-471d-b2d4-6a825e895dd4

09/25/19 10:31:08 -- Used named pipe impersonation in memory.
    d310377d-9625-4645-a0e0-17b08addb7d3

09/25/19 10:32:11 -- On Sysclient0051, used meterpreter to get cmd shell. Ran commands to find out information about local system.
    7fa3e75b-196a-47d4-9f2a-65f0e61de408

09/25/19 10:33:55 -- On Sysclinet0051, used arp scanner on 142.20.56.0/22
    ARP traffic is not captured by the monitoring agent.

09/25/19 10:36:28 -- On Sysclient0051, used meterpreter enum modules to discover all installed applications
    The raw event corresponding to this line was not discovered.

09/25/19 10:37:52 -- On Sysclient0051 used meterpreter enum_domain modules to identify domain controller
    The raw event corresponding to this line was not discovered.

09/25/19 10:38:35 -- On Sysclient 0051, used meterpreter enum_shares to identify any shares on host
    The raw event corresponding to this line was not discovered.

09/25/19 10:40:39 -- On Sysclient 0051, migrated from process 2712 cKfGW.exe to lsass 568
    6828b8c3-bbcb-4ecd-9e2a-abe50951b50a

09/25/19 10:44:56 -- On Sysclient0051, ran mimikatz to collect cleartext passwords and hashes
    The raw event corresponding to this line was not discovered.

09/25/19 10:48:43 -- On Sysclient0051, established persitence via meterpreter. Script written to C:\\Windows\\TEMP\\myHbYXTpViwX.vbx. Installed Autorun at HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\RTqWaEHv
    fa8b1706-4550-4715-bf6b-8ffba87c709b

09/25/19 10:53:06 -- On Sysclient0051, used timestomp to edit MAC times of crated files in C:\\Windows\\TEMP
    13fd460d-e5dd-4be9-a466-af826afee6af

09/25/19 11:07:41 -- On Sysclient0051, used get_gui to add administrator \"admin\" to administrators and RDP group
    f4cc81b2-1bdc-4d84-8ec1-20019957206c

09/25/19 11:23:31 -- On Sysclient0351, conducted update to notepadd++, which downloaded malicous update.exe binary which made connection back to attacker server
    1bd1faba-97e3-4676-b368-49e1e320a63b

09/25/19 11:24:30 -- On Sysclient0351, migrated from process 1932 to 1256 lwabeat.
    789fe2c1-c59c-4ae6-933d-1bac24ff21e9

09/25/19 13:42:05 -- On Sysclient0051, RDPed to machine from attacker server.
    02eceae7-7b57-412b-b797-2be879b5f07f

09/25/19 14:24:03 -- Reran updated.exe on Sysclient0051
    697aa9d7-b75f-4acc-b540-6132a6ef617f
```

This listing can be extracted from the `tasks.json` using the following command:

```bash
cat tasks.json | jq '.[] | {log, event_id, annotations} | select(.log != "")'
```
