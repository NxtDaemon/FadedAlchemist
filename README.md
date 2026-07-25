<p align="center">
  <img src="images/logo.png" style="max-width: 300px"/>
</p>

# FadedAlchemist — Registry Malware Artefact Discovery

FadedAlchemist detects malware-induced Windows Registry modifications. Point it at a directory of collected hives — e.g. output from [Acquire](https://github.com/fox-it/acquire) — and it will extract persistence mechanisms, statistically anomalous values, and results from regipy's built-in forensic plugins.

## What it does
- **Persistence discovery (ASEP)** — Detects known Auto-Start Extensibility Points (Run keys, scheduled tasks, services) for ASEP vectors.
- **Statistical artefact analysis** — Scores extracted values on Shannon entropy, Chi-Squared Randomness, Length, and Flags (IP/URL/B64D Detection) to surface values that look attacker-planted rather than legitimate configuration.
- **Baselining** — collect a "known good" baseline from a clean device and subtract it from a sample to cut straight to what changed.
- **regipy plugin integration** — runs any of regipy's 70+ bundled artefact plugins (Amcache, ShimCache, UserAssist, Shellbags, etc.) against the collected hives.
- **Transaction log replay** — detects dirty hives and can replay their `.LOG1`/`.LOG2` transaction logs to recover the latest state before analysis.

## Installation

Requires Python 3.11+.

```
pip install -r requirements.txt
```

FadedAlchemist V2 uses the new accelerated [regipy Rust backend](https://github.com/mkorman90/regipy) which speeds up key extraction around 600x

## Usage

Faded Alchemist is invoked as `Alchemist.py <mode> -d <path> [options]`. Every mode reads hives from the given directory; which files count as hives, and which subdirectories are skipped as duplicates/irrelevant (e.g. `regback`, `Default`), is defined in `Alchemist.HIVE_NAMES`/`DEFEAT_DIRECTORIES`.

| Mode            | Description                                                                        |
| --------------- | ---------------------------------------------------------------------------------- |
| `comprehensive` | Runs both `persistence` and `artefacts` analysis                                   |
| `persistence`   | Discovers ASEP persistence mechanisms only (fast — skips full key extraction)      |
| `artefacts`     | Runs the statistical entropy/chi-squared/length/marks analysis only                |
| `plugins`       | Runs regipy's built-in artefact plugins against each hive                          |
| `list-plugins`  | Lists every available regipy plugin (name, compatible hive, description) and exits |

### Collect a baseline (optional)

Run against a clean reference image so its values can be subtracted from later scans:

```
python .\Alchemist.py comprehensive -d X:\Path\To\Acquire\Collection --collect-baseline
```

### Scan a sample, reduced against a baseline

```
python .\Alchemist.py comprehensive -d X:\Path\To\Acquire\Collection --use-baseline .\baseline\BaselineData_xxxx.p -n MySampleName
```

### Persistence-only scan (fastest)

```
python .\Alchemist.py persistence -d X:\Path\To\Acquire\Collection
```

### Run regipy plugins

```
python .\Alchemist.py plugins -d X:\Path\To\Acquire\Collection --plugins amcache,shimcache
```

## Output

Every run creates an output directory named after `--name` (or a random designator if omitted), containing:

| File                                             | Produced by                   | Contents                                                                |
| ------------------------------------------------ | ----------------------------- | ----------------------------------------------------------------------- |
| `<name>_ASEP_Results.{json,csv}`, `ASEP.table`   | `persistence`/`comprehensive` | Discovered autoruns, scheduled tasks, and services                      |
| `<name>_Results.{json,csv,p}`, `Alchemist.table` | `artefacts`/`comprehensive`   | Values that passed the entropy/length/marks "meaningful" filter         |
| `<name>_Plugins.{json,csv}`, `Plugins.table`     | `plugins`                     | Per-hive results from each regipy plugin that ran                       |
| `BaselineData_<name>.{json,p}`                   | `--collect-baseline`          | Every extracted value, for use as `--use-baseline` input on a later run |

`.table` files are plain-text snapshots of the Rich tables printed to console, for easy diffing/review outside a terminal.

### Example output (ASEP)

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

### Example output (Artefacts)

```
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| HIVE     | Key_Path                                                                                             | TS                  | Value_Name          | Value_Type | Value                               | Entropy            | ChiSquared         | Length | Marks      |
|----------+------------------------------------------------------------------------------------------------------+---------------------+---------------------+------------+-----------------------------------------------------------------------------------------------------|
| NTUSER   | \Software\Microsoft\Windows\DWM                                                                      | 2025-03-26 11:55:16 | fjhsfgds            | REG_SZ     | 191_62_106_23                       | 2.6612262562697895 | N/a                | 13     | ['IP']     |
| NTUSER   | \Software\Microsoft\Windows\DWM                                                                      | 2025-03-26 11:55:16 | 6e5cb5301           | REG_SZ     | QQBkAGQALQBUAHkAcABlACAALQBUAHk.... | 4.120352779215068  | N/a                | 256    | ['Base64'] |
| NTUSER   | \Software\Microsoft\Windows\DWM                                                                      | 2025-03-26 11:55:16 | 6e5cb530c           | REG_SZ     | https://4ad74aab.fun/index.php      | 4.031401845392171  | N/a                | 30     | ['URL']    |
| SYSTEM   | \ControlSet001\Control\ProductOptions                                                                | 2025-03-26 11:51:44 | ProductPolicy       | REG_BINARY | <BINARY_DATA>                       | 3.3582123455953075 | 3980355.8894219045 | 49196  | []         |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
```

## CLI Reference

```
usage: FADED ALCHEMIST [-h] {comprehensive,persistence,artefacts,plugins,list-plugins} ...

Capability to enable detection of malware-induced Windows Registry modifications

positional arguments:
  {comprehensive,persistence,artefacts,plugins,list-plugins}
                        Scan mode to run
    comprehensive       Perform ALL Available Analysis
    persistence         Discover Persistence on Device via the Registry
    artefacts           Perform Statistical Analysis of the Registry
    plugins             Run regipy's built-in artefact plugins against each hive
    list-plugins        List all available regipy plugins and exit

options:
  -h, --help            show this help message and exit
```

`comprehensive`, `persistence`, `artefacts`, and `plugins` all share the same set of options:

```
  -d, --directory PATH  Specify the directory where registry files are stored
  --restore-hives       Replay Registry Transaction Logs into Hives Where Possible
  --drop-unknown-reg-types
                        Drop values with an unrecognized registry type
  --format {JSON,CSV,ALL}
                        Enable JSON or CSV for output formats
  --show-locations      Include the registry key location/path as a column in output
  --collect-baseline    Dumps Extracted Values JSON & Pickle to Deduplicate Against
  --use-baseline USE_BASELINE
                        Uses Extracted Values JSON/Pickle file to Deduplicate Against
  --shannon_threshold SHANNON_THRESHOLD
  --length_threshold LENGTH_THRESHOLD
  --dynamic-length-purging
  --plugins PLUGINS     Comma-separated regipy plugin names to run (default: all validated plugins)
  --include-unvalidated-plugins
                        Also run regipy plugins without validation test cases
  --verbose, -v         Increase logging verbosity, e.g. -v enables DEBUG logging
  --name, -n NAME       Assign a designator to a scan, all saved files used this to identify multiple runs
```

`list-plugins` takes no options besides `-h`.

## License

MIT — see [LICENSE](LICENSE).
