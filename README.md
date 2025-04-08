<p align="center"">
  <img src="https://github.com/user-attachments/assets/687ae19c-c6e5-4a24-8b31-03ac6cef5974" />
</p>


# Faded Alchemist - Registry Malware Artefact Discovery

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
