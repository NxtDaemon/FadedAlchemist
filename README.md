<p align="center"">
  <img src="https://github.com/user-attachments/assets/687ae19c-c6e5-4a24-8b31-03ac6cef5974" />
</p>


# Faded Alchemist - Registry Malware Artefact Discovery
FadedAlchemist is an MVP for malware-induced Windows Registry modification detection that uses the [Acquire](https://github.com/fox-it/acquire) project to perform samples collections from VMs

## How to Run Faded Alchemist 
The following commands show how to run FadedAlchemist in it's intended format

### Collect Baseline Data (Optional)

```
> python .\Alchemist.py -c -D X:\Path\To\Acquire\Collection --collect-baseline
```

### Process Sample with Baseline Reduction 

```
python .\Alchemist.py -c -D X:\Path\To\Acquire\Collect --use-baseline .\baseline.p -N MySampleName
```

#### Example Output (ASEP)
```
                                                                                       ASEP Keys                                                                                        
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Method         | Value                                                                                                               | Context                                       |
|----------------+---------------------------------------------------------------------------------------------------------------------+-----------------------------------------------|
| SCHEDULED_TASK | 6e5cb530-6e5c-b530-6e5c-6e5cb5306e50                                                                                | {76F7B83F-12AD-4370-A37F-538F2344A0A5}        |
| SCHEDULED_TASK | SetupCleanupTask                                                                                                    | {AF2FFE13-7176-45EB-BE68-FEA1ABC76588}        |
| SCHEDULED_TASK | Schedule Retry Scan                                                                                                 | {E9726D33-EC6C-4A01-BBAB-CEDF22B8F14C}        |
| SCHEDULED_TASK | MicrosoftEdgeUpdateTaskUserS-1-5-21-4087482164-2601983007-2479528554-1000Core{309F9EAF-9287-4133-A1C2-EF9E09A1031E} | {9426D946-2504-4F3F-AA13-C0B248516004}        |
| SCHEDULED_TASK | MicrosoftEdgeUpdateTaskUserS-1-5-21-4087482164-2601983007-2479528554-1000UA{098FAE39-29ED-43ED-80CB-0125542E393E}   | {1450C988-13B2-4C9E-8A39-6984C6D3331F}        |
| SCHEDULED_TASK | OneDrive Standalone Update Task-S-1-5-21-4087482164-2601983007-2479528554-1000                                      | {F6D52563-1A2E-4E3E-918F-9D7A125B017B}        |
| SCHEDULED_TASK | OneDrive Startup Task-S-1-5-21-4087482164-2601983007-2479528554-1000                                                | {37143E27-DF80-4839-B6EA-A88669EC03F1}        |
| HKLM_SERVICE   | CDPUserSvc_32dfc                                                                                                    | Connected Devices Platform User Service_32dfc |
| HKLM_SERVICE   | DevicesFlowUserSvc_32dfc                                                                                            | DevicesFlow_32dfc                             |
| HKLM_SERVICE   | MessagingService_32dfc                                                                                              | MessagingService_32dfc                        |
| HKLM_SERVICE   | OneSyncSvc_32dfc                                                                                                    | Sync Host_32dfc                               |
| HKLM_SERVICE   | PimIndexMaintenanceSvc_32dfc                                                                                        | Contact Data_32dfc                            |
| HKLM_SERVICE   | UnistoreSvc_32dfc                                                                                                   | User Data Storage_32dfc                       |
| HKLM_SERVICE   | UserDataSvc_32dfc                                                                                                   | User Data Access_32dfc                        |
| HKLM_SERVICE   | WpnUserService_32dfc                                                                                                | Windows Push Notifications User Service_32dfc |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
```

#### Example Output (Artefacts)
```
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| HIVE     | Key_Path                                                                                             | TS                  | Value_Name          | Value_Type | Value                               | Entropy            | ChiSquared         | Length | Marks      |
|----------+------------------------------------------------------------------------------------------------------+---------------------+---------------------+------------+-----------------------------------------------------------------------------------------------------|
| NTUSER   | \Software\Microsoft\EdgeUpdate\Clients\{F3C4FE00-EFD5-403B-9569-398A20F1BA4A}                        | 2025-03-26 11:51:59 | pv                  | REG_SZ     | 1.3.195.45                          | 2.4464393446710155 | N/a                | 10     | ['IP']     |
| NTUSER   | \Software\Microsoft\EdgeUpdate\ClientState\{F3C4FE00-EFD5-403B-9569-398A20F1BA4A}                    | 2025-03-26 11:51:59 | pv                  | REG_SZ     | 1.3.195.45                          | 2.4464393446710155 | N/a                | 10     | ['IP']     |
| NTUSER   | \Software\Microsoft\EdgeUpdate                                                                       | 2025-03-26 11:52:31 | version             | REG_SZ     | 1.3.195.45                          | 2.4464393446710155 | N/a                | 10     | ['IP']     |
| NTUSER   | \Software\Microsoft\Windows\DWM                                                                      | 2025-03-26 11:55:16 | fjhsfgds            | REG_SZ     | 191_62_106_23                       | 2.6612262562697895 | N/a                | 13     | ['IP']     |
| NTUSER   | \Software\Microsoft\Windows\DWM                                                                      | 2025-03-26 11:55:16 | 6e5cb5301           | REG_SZ     | QQBkAGQALQBUAHkAcABlACAALQBUAHk.... | 4.120352779215068  | N/a                | 256    | ['Base64'] |
| NTUSER   | \Software\Microsoft\Windows\DWM                                                                      | 2025-03-26 11:55:16 | 6e5cb530c           | REG_SZ     | https://4ad74aab.fun/index.php      | 4.031401845392171  | N/a                | 30     | ['URL']    |
| SOFTWARE | \Microsoft\Windows Defender\Signature Updates                                                        | 2025-03-26 11:57:09 | NISSignatureVersion | REG_SZ     | 119.0.0.0                           | 1.8910611120726526 | N/a                | 9      | ['IP']     |
| SOFTWARE | \Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{1450C988-13B2-4C9E-8A39-6984C6D3331F} | 2025-03-26 11:57:46 | Version             | REG_SZ     | 1.3.195.45                          | 2.4464393446710155 | N/a                | 10     | ['IP']     |
| SOFTWARE | \Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{9426D946-2504-4F3F-AA13-C0B248516004} | 2025-03-26 11:51:59 | Version             | REG_SZ     | 1.3.195.45                          | 2.4464393446710155 | N/a                | 10     | ['IP']     |
| SYSTEM   | \ControlSet001\Control\ProductOptions                                                                | 2025-03-26 11:51:44 | ProductPolicy       | REG_BINARY | <BINARY_DATA>                       | 3.3582123455953075 | 3980355.8894219045 | 49196  | []         |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
```

## Tool Options 
```
usage: FADED ALCHEMIST [-h] --directory DIRECTORY [--restore_hives] [--merge_dfs] [--drop_unknown_reg_types]
                       [--format {JSON,CSV,ALL}] [--csv] [--json] [--collect-baseline] [--use-baseline USE_BASELINE]
                       [--comprehensive] [--persistence] [--artefacts] [--shannon_threshold SHANNON_THRESHOLD]
                       [--length_threshold LENGTH_THRESHOLD] [--dynamic-length-purging] [--verbose] [--name NAME]

Capability to enable detection of malware-induced Windows Registry modifications

options:
  -h, --help            show this help message and exit
  --directory DIRECTORY, -D DIRECTORY
                        Specify the directory where registry files are stored
  --restore_hives       Replay Registry Transaction Logs into Hives Where Possible
  --merge_dfs           Merge All Results in one DataFrame Instead of Per-Hive
  --drop_unknown_reg_types
                        Merge All Results in one DataFrame Instead of Per-Hive
  --format {JSON,CSV,ALL}
                        Enable JSON or CSV for output formats
  --csv                 Enable CSV Mode for Output
  --json                Enable JSON Mode for Output
  --collect-baseline    Dumps Extracted Values JSON & Pickle to Deduplicate Against
  --use-baseline USE_BASELINE
                        Uses Extracted Values JSON/Pickle file to Deduplicate Against
  --comprehensive, -c   Perform ALL Available Analysis
  --persistence, -p     Discover Persistence on Device via the Registry
  --artefacts, -art     Perform Statistical Analysis of the Registry
  --shannon_threshold SHANNON_THRESHOLD
  --length_threshold LENGTH_THRESHOLD
  --dynamic-length-purging
  --verbose, -v         Verbose logging (i.e Enable DEBUG Mode)
  --name NAME, -n NAME  Assign a designator to a scan, all saved files used this to identify multiple runs
```
