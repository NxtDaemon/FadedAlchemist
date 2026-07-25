import argparse
import base64
import binascii
import json
import logging
import math
import pickle
import re
import secrets
import statistics
import time
from collections import Counter
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Any

import pandas as pd

try:
    #* Try importing the Regipy Rust Backend and use that
    from regipy.registry_rs import RegistryHive
except ImportError:
    #* If not available, fail back to the Python Backend
    from regipy.registry import RegistryHive

import tldextract
from regipy.exceptions import (NoRegistrySubkeysException,
                               RegistryKeyNotFoundException)
from regipy.plugins.plugin import PLUGINS
from regipy.plugins.utils import run_relevant_plugins
from regipy.recovery import apply_transaction_logs
from regipy.structs import VALUE_TYPE_ENUM
from regipy.utils import convert_wintime
from rich import inspect
from rich.console import Console
from rich.json import JSON
from rich.progress import (BarColumn, MofNCompleteColumn, Progress, TextColumn,
                           TimeRemainingColumn)
from rich.status import Status
from rich.table import Table
from scipy.stats import chisquare

pd.set_option('display.max_rows', None)

#* Make regipy less verbose
logging.getLogger("regipy").setLevel(logging.ERROR)

def df2table(df,title=""):
    #* Create Rich.Table and Populate with Results
    t = Table(title=title)

    #* Add Columns        
    for col in df.columns:
        t.add_column(col)
        
    #* Add Rows
    #* Structured (dict/list) cells get rich JSON syntax highlighting instead of a raw str() dump
    for index, row in df.iterrows():
        t.add_row(*[JSON.from_data(val, indent=None) if isinstance(val,(dict,list)) else str(val) for val in row])
    
    return t  

def Try_Unhexlify_Or_Return(value):
    '''Function to be used in Lambda functions whereby data might be hexlified but could error'''
    try:
        return binascii.unhexlify(value)
    except Exception as E:
        return value

class RegType_JSON_Serialiser(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            #* Convert Bytes to HEX to enable in JSON for REG_BINARY
            return binascii.hexlify(obj).decode('utf-8')
        
        elif isinstance(obj, datetime):
            #* Convert Timestamps for REG_FILETIME into epoch time int
            return obj.timestamp()
        
        return super().default(obj)
        
class RegistryCollection():
    def __init__(self):
        self.hives = {}
    
    def get_hive(self, hkey : str):
        """Method to get a specific hive"""
        return self.hives.get(hkey.lower(),None)
    
    def add_hive(self, hive : RegistryHive, key : str = None):
        """Method to add Add to Collection. Defaults to keying by hive_type, but an explicit
        key can be passed to disambiguate hives that share a type (e.g. NTUSER.DAT per-user)"""
        self.hives.update({(key or hive.hive_type).lower() : hive})
        
    def get_added_hives_u(self):
        """Method to return all hives in UPPERCASE"""
        return [hive.upper() for hive in self.hives]
        
    def get_added_hives(self):    
        """Method to return all hives in LOWERCASE"""
        return [hive for hive in self.hives]

class Alchemist():
    TOOL_CONSOLE_PROMPT = "[spring_green1]FADED ALCHEMIST[/]"

    #* Rich colors assigned per log level
    LEVEL_STYLES = {
        "DEBUG": "grey58",
        "INFO": "cyan",
        "WARNING": "orange1",
        "ERROR": "bold red",
    }

    #* Width of the longest bracketed level tag (e.g. "[WARNING]"), used to
    #* pad shorter tags with trailing spaces so messages line up
    TAG_WIDTH = max(len(level) for level in LEVEL_STYLES) + 2

    #* Hives that we are interested in
    HIVE_NAMES = ["SYSTEM","SOFTWARE","SECURITY","SAM","NTUSER.DAT"]
    
    #* Directories where copies or irrelevant HIVES are also stored
    DEFEAT_DIRECTORIES = ["regback","LocalService","Default","NetworkService"]
    #! Regback - Backups of the registry used in recovery
    #! Default - HKCU of the default user, copied template for new users
    #! LocalService - HKCU for the LocalService SID
    #! NetworkService - HKCU for the NetworkService SID
    
    #* Object to store hive files
    REGISTRY = RegistryCollection()
    Extracted_Dict = {}

    #* ASEP (Auto-Start Extensibility Point) locations - shared between the full
    #* extraction-based scan and the targeted, extraction-free persistence-only scan
    #* Has removed SOFTWARE/SYSTEM etc as this isn't loaded into an actual registry and those paths wont resolve correctly
    ASEP_RUNKEYS = {
        '\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit',
        '\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',
        '\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
        '\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run',
        '\\CurrentControlSet\\Control\\Session Manager\\BootExecute',
        '\\CurrentControlSet\\Control\\Session Manager\\SubSystems',
        '\\Microsoft\\Windows\\CurrentVersion\\Run',
        '\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
        '\\Environment\\UserInitMprLogonScript',
        '\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell',
        '\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
    }

    #* Both Tree and Tasks will also fit this starter
    ASEP_SCHEDULED_TASK_PREFIX = r"\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
    #* Holds the actual task definition (Path, Actions, etc) keyed by the GUID found under ASEP_SCHEDULED_TASK_PREFIX
    ASEP_SCHEDULED_TASK_DETAILS_PREFIX = r"\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks"
    ASEP_HKCU_SERVICE_PREFIX = r"\Microsoft\Windows NT\CurrentVersion\Services"
    ASEP_HKLM_SERVICE_PREFIX = r"\ControlSet001\Services"

    #* Subtree prefixes need a scoped recursive walk, unlike the single-value ASEP_RUNKEYS
    ASEP_SUBTREE_PREFIXES = (ASEP_SCHEDULED_TASK_PREFIX, ASEP_SCHEDULED_TASK_DETAILS_PREFIX, ASEP_HKCU_SERVICE_PREFIX, ASEP_HKLM_SERVICE_PREFIX)

    #* Windows service Start value -> human-readable start type
    SERVICE_START_TYPES = {0 : "Boot", 1 : "System", 2 : "Automatic", 3 : "Manual", 4 : "Disabled"}

    def __init__(self, args : dict, console : Console = Console()):
        self.console = console
        
        self.registry_files = args.directory

        #* -v (count) sets both our own DEBUG-level messages and regipy's internal logger
        self.DEBUG_MODE = args.verbose > 0
        logging.getLogger("regipy").setLevel(logging.DEBUG if args.verbose > 0 else logging.ERROR)

        #* Fall back to a random designator so saved files/tables never end up named "None"
        self.DESIGNATOR = args.name or secrets.token_hex(4)

        self.CSV_MODE = args.csv
        self.JSON_MODE = args.json

        self._print(f"Output mode set to '{args.format}'")

        self._print(f"Assigned designator '{self.DESIGNATOR}'")
        self.OUTPUT_DIR = Path().joinpath(self.DESIGNATOR)

        if not self.OUTPUT_DIR.exists():
            self.OUTPUT_DIR.mkdir()
            self._print(f"Created output directory '{self.OUTPUT_DIR}'")
        else:
            self._print(f"Using output directory '{self.OUTPUT_DIR}'")

        #* Baseline Args
        self.COLLECT_BASELINE = args.collect_baseline
        self.Baseline_Data = args.use_baseline
        
        #* Processing Args
        self.RESTORE_HIVES = args.restore_hives
        self.DROP_UNKNOWN = args.drop_unknown_reg_types
        self.DLP = args.dynamic_length_purging
        self.SHANNON_THRESHOLD = args.shannon_threshold or 5.7
        self.LENGTH_THRESHOLD = args.length_threshold or 4096
        self.asep = args.persistence
        self.RUN_ARTEFACTS = args.artefacts
        self.SHOW_LOCATIONS = args.show_locations

        #* Plugin Args
        self.RUN_PLUGINS = args.mode == "plugins"
        self.PLUGIN_NAMES = {name.strip() for name in args.plugins.split(",")} if args.plugins else None
        self.INCLUDE_UNVALIDATED_PLUGINS = args.include_unvalidated_plugins

        #* When persistence is the only mode running, ASEP locations can be queried
        #* directly, skipping the full key extraction that artefacts/comprehensive need
        self.PERSISTENCE_ONLY = self.asep and not self.RUN_ARTEFACTS

        #* Plugins is its own standalone mode that operates directly on RegistryHive
        #* objects, so it never needs the full key/value extraction pass either
        self.SKIP_EXTRACTION = self.PERSISTENCE_ONLY or self.RUN_PLUGINS

        #* Collect Registry Files
        self._resolve_registry_files()

        collected_hives = self.REGISTRY.get_added_hives_u()

        self._print(f"Loaded {len(collected_hives)} hive(s): {collected_hives}")

        if self.PERSISTENCE_ONLY and (self.COLLECT_BASELINE or self.Baseline_Data):
            self._print("Baseline options have no effect in persistence-only mode, since no keys are extracted", level="WARNING")

        #* Start timer and start hive value extraction
        T1 = datetime.now()

        if not self.SKIP_EXTRACTION:
            self._extract_values_from_hives()

            #* If Baseline Data is detected remove all baseline data
            if self.Baseline_Data:
                self._eliminate_baseline()

        T2 = datetime.now()
        self._print(f"Finished processing device in {T2 - T1}")

        if self.RUN_ARTEFACTS:
            self._add_analytics()

        if self.asep:
            if self.PERSISTENCE_ONLY:
                self._find_asep_targeted()
            else:
                self._find_asep()

        if self.RUN_PLUGINS:
            self._run_plugins()

        T3 = datetime.now()
        self._print(f"Finished analyzing device in {T3 - T2}")

        if self.RUN_ARTEFACTS:
            self._get_meaningful_results()
        
        
    def _write_table(self,t,name):
        with self.OUTPUT_DIR.joinpath(f"{name}.table").open("wt") as report_file:
            console = Console(file=report_file,width=700)
            console.print(f"Writing {name} Table - {datetime.now().ctime()}\n\n\n")
            console.print(t)
                
    def _format_message(self, message : str, level: str = "INFO") -> str:
        """Builds the timestamped, leveled, colored line shared by _print and any live rich widgets (e.g. Progress)"""
        style = self.LEVEL_STYLES.get(level, "white")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return f"{timestamp} - {self.TOOL_CONSOLE_PROMPT} - [{style}]{level}:[/{style}] {message}"

    def _print(self,message : str, level: str = "INFO"):
        """Method to print timestamped, leveled log messages to the console via rich"""

        if level == "DEBUG" and not self.DEBUG_MODE:
            return

        self.console.print(self._format_message(message, level))

    def _eliminate_baseline(self):
        """Method to remove previously seen data (Baseline data) from the Extracted_Dict"""
        self._print(f"Reading baseline from '{self.Baseline_Data.resolve()}'")
        
        JSON_BASELINE = False
        
        if self.Baseline_Data.suffix.lower() == ".json":
            #* Load as JSON 
            with self.Baseline_Data.open("r") as f:
                BaselineExtracted = json.load(f)
                JSON_BASELINE = True
        
        elif self.Baseline_Data.suffix.lower() == ".p":
            #* Load as Pickle
            with self.Baseline_Data.open("rb") as f:
                BaselineExtracted = pickle.load(f)
            
        Baseline_Records_Summary = {k.upper() : len(v) for k,v in BaselineExtracted.items()}
        Total_Records = sum(len(arr) for arr in BaselineExtracted.values())
        Total_Records_Removed = 0
        self._print(f"Read {Total_Records} baseline record(s): {Baseline_Records_Summary}")
        
        for hive_name in self.Extracted_Dict:
            Hive_Extracted_Values = self.Extracted_Dict.get(hive_name,None)
            Baseline_Extracted_Values = BaselineExtracted.get(hive_name,None)
            Start_Amount_Of_Records = len(Hive_Extracted_Values)
            
            if not all([Hive_Extracted_Values,Baseline_Extracted_Values]):
                continue
            
            #* Put all Active Data Under DF - A and Mark it as ACTIVE in the lineage column
            df_A = pd.DataFrame(Hive_Extracted_Values)
            df_A = df_A.assign(lineage="ACTIVE")

            #* put all Baseline Data under DF - B and Mark it as BASELINE in the lineage column
            df_B = pd.DataFrame(Baseline_Extracted_Values)
            df_B = df_B.assign(lineage="BASELINE")
            
            if JSON_BASELINE:
                #! Baseline Data has REG_BINARY value as Bytes Hexlified so lets reverse this
                #? Weird Behaviour Observed, implemented and number increase (pandas may use hexlify under the hood so this can be ignored)
                #? df_B["Value"] = df_B.apply(lambda row: Try_Unhexlify_Or_Return(row["Value"]) if row["Value_Type"] == "REG_BINARY" else row["Value"], axis=1)
                
                #! Baseline Data has REG_FILENAME value as epoch time so reverse this
                df_B["Value"] = df_B.apply(lambda row: datetime.fromtimestamp(row["Value"], tz=UTC) if row["Value_Type"] == "REG_FILETIME" else row["Value"], axis=1)

            #! Fixes an issue with using Lists for REG_MULTI_SZ uses frozenset to fix this
            df_B["Value"] = df_B.apply(lambda row: frozenset(row["Value"]) if row["Value_Type"] == "REG_MULTI_SZ" else row["Value"], axis=1)
            df_A["Value"] = df_A.apply(lambda row: frozenset(row["Value"]) if row["Value_Type"] == "REG_MULTI_SZ" else row["Value"], axis=1)

            #* Create a subset to ignore the lineage column
            subset = ["Key_Path","Value_Name","Value_Type","Value"]

            #* Merge dataframes dropping any non-unique entries
            df_merged = pd.concat([df_A, df_B]).drop_duplicates(subset=subset, keep=False)
            
            #* Remove any BASELINE data that could have flowed into the merged DF (i.e. enforce AuB')
            df_merged = df_merged[df_merged["lineage"] != "BASELINE"]
            df_merged = df_merged.drop(columns=["lineage"])
            
            #! Reverse Frozenset Conversion
            df_merged["Value"] = df_merged.apply(lambda row: list(row["Value"]) if row["Value_Type"] == "REG_MULTI_SZ" else row["Value"], axis=1)
            
            Deduplicated_Data = df_merged.to_dict("records")
            End_Amount_Of_Records = len(Deduplicated_Data)
            Record_Delta = Start_Amount_Of_Records - End_Amount_Of_Records
            Total_Records_Removed += Record_Delta
            
            self._print(f"Removed {Record_Delta} baseline record(s) from '{hive_name.upper()}', {End_Amount_Of_Records} remaining")
            self.Extracted_Dict.update({hive_name : Deduplicated_Data})

        self._print(f"Removed {Total_Records_Removed} baseline record(s) in total")

        Data_Reduction_Percentage = (Total_Records_Removed / self.total_records_extracted) * 100
        self._print(f"Total data reduction: {Data_Reduction_Percentage:.2f}%")

    def _extract_values_from_hives(self):
        """Method to kickoff analysis of all hives"""
        hives_names = self.REGISTRY.get_added_hives()
        values_extracted = 0
        
        with Status("[bold green] Processing", spinner="earth",console=self.console) as status:
                    
            for hive_name in hives_names:
                hive = self.REGISTRY.get_hive(hive_name)
                if not hive:
                    continue 
                
                status.update(f"Starting extraction of '{hive.hive_type.upper()}'")
                
                #* Use List Comprehension for Speed & Opti, get all entries first
                hive_entries = [entry for entry in hive.recurse_subkeys()]
                
                #* Extract Meaningful Values from Entry and Value
                extracted_values = [
                    {"Key_Path" : entry.path,
                    "TS" : entry.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    "Value_Name" : value.name,
                    "Value_Type" : str(value.value_type), 
                    "Value" : value.value}
                        for entry in hive_entries for value in entry.values]
                
                #* Drop Unknown Registry Types (See Report for more Info)
                #* Couldnt get enum presence checking to work, so just drop all valid integers 
                #! Inconsistency in Regipy for ControlSet value_types where they are ints not strings (fixed by casting to str)
                if self.DROP_UNKNOWN:
                    extracted_values = [entry for entry in extracted_values if not entry["Value_Type"].isdigit()]

                values_extracted += len(extracted_values)
                self._print(f"Extracted {len(extracted_values)} value(s) from '{hive_name.upper()}'")

                self.Extracted_Dict[hive_name] = extracted_values

            self._print(f"Extracted {values_extracted} value(s) in total")
            self.total_records_extracted = values_extracted
            
            if self.COLLECT_BASELINE:
                with self.OUTPUT_DIR.joinpath(f"BaselineData_{self.DESIGNATOR}.json").open("w") as f:
                    json.dump(self.Extracted_Dict,f, cls=RegType_JSON_Serialiser)
                    
                with self.OUTPUT_DIR.joinpath(f"BaselineData_{self.DESIGNATOR}.p").open("wb") as f:
                    pickle.dump(self.Extracted_Dict,f)
            
    
    def _resolve_registry_files(self):
        HIVES = [file for file in self.registry_files.rglob("*") if 
                    file.is_file() and 
                    file.name in self.HIVE_NAMES and 
                    file.parent.name not in self.DEFEAT_DIRECTORIES
                ]

        self._print(f"Discovered {len(HIVES)} hive(s): {[f.name for f in HIVES]}")
        
        with self.console.status("Resolving Registry Hives", spinner="moon"):
            for HIVE in HIVES:
                time.sleep(0.1)

                h = RegistryHive(HIVE)

                #* NTUSER.DAT is per-user, so keying purely by hive_type would collide across
                #* profiles - key it by the owning username (the hive's parent directory) instead
                hive_key = f"NTUSER[{HIVE.parent.name}]" if HIVE.name == "NTUSER.DAT" else None

                if (h.header.primary_sequence_num != h.header.secondary_sequence_num):
                    #* If the hive is dirty then lets discover the LOG files for this
                    self._print(f"Dirty hive detected: '{HIVE.name}' (primary sequence {h.header.primary_sequence_num}, secondary sequence {h.header.secondary_sequence_num})", level="WARNING")

                    if not self.RESTORE_HIVES:
                        #* Only replay transactions if this argument is enabled
                        self.REGISTRY.add_hive(h, key=hive_key)
                        continue

                    #* Search for only LOG1 and LOG2 files of the same name in the same directory
                    LOGS = list(HIVE.parent.rglob(f"*{HIVE.name}.LOG[12]"))
                    self._print(f"Discovered {len(LOGS)} transaction log(s) for {HIVE.name}: {[f.name for f in LOGS]}",level="DEBUG")

                    #* Assign only the correct logs to the right variable and ensure that the file is actually populated as Regipy doesnt check for this

                    primary_log = [f for f in LOGS if f.suffix == ".LOG1" and f.stat().st_size > 0]
                    primary_log = primary_log[0] if primary_log else None

                    secondary_log = [f for f in LOGS if f.suffix == ".LOG2" and f.stat().st_size > 0] or None
                    secondary_log = secondary_log[0] if secondary_log else None

                    self._print(f"Valid transaction log(s) for {HIVE.name}: {[x.name for x in [primary_log,secondary_log] if x != None]}",level="DEBUG")

                    try:
                        #* Create a restored hive by applying transaction logs onto the hive
                        restored_hive, dirty_hive_count = apply_transaction_logs(HIVE,primary_log_path=primary_log,secondary_log_path=secondary_log,verbose=True)
                        self._print(f"Replayed {dirty_hive_count} transaction(s) into '{HIVE.name}'")
                        h = RegistryHive(restored_hive)
                        self.REGISTRY.add_hive(h, key=hive_key)
                    except:
                        self.REGISTRY.add_hive(h, key=hive_key)

                else:
                    self.REGISTRY.add_hive(h, key=hive_key)
                    self._print(f"Hive '{HIVE.name}' passed all integrity checks",level="DEBUG")

    def _run_plugins(self):
        '''Runs regipy's built-in artefact plugins against every collected hive.
        Plugin compatibility is matched against each hive's actual hive_type,
        independent of the key it was stored under in the RegistryCollection'''
        self._print(f"Running plugins ({len(PLUGINS)} available, {'all' if not self.PLUGIN_NAMES else ', '.join(sorted(self.PLUGIN_NAMES))})")

        self.Plugin_Results = {}

        with Status("[bold green] Running plugins", spinner="dots", console=self.console) as status:
            for hive_name in self.REGISTRY.get_added_hives():
                hive = self.REGISTRY.get_hive(hive_name)
                if not hive:
                    continue

                status.update(f"Running plugins against '{hive_name.upper()}'")

                results = run_relevant_plugins(
                    hive,
                    as_json=True,
                    plugins=self.PLUGIN_NAMES,
                    include_unvalidated=self.INCLUDE_UNVALIDATED_PLUGINS,
                )

                #* Only keep plugins that actually produced entries
                results = {name: entries for name, entries in results.items() if entries}

                if results:
                    self._print(f"'{hive_name.upper()}': {len(results)} plugin(s) with results - {list(results.keys())}")
                    self.Plugin_Results[hive_name] = results

        if self.JSON_MODE:
            with self.OUTPUT_DIR.joinpath(f"{self.DESIGNATOR}_Plugins.json").open("w") as f:
                json.dump(self.Plugin_Results, f, cls=RegType_JSON_Serialiser, indent=2)

        #* Plugin output shapes vary per-plugin, so CSV only gets the summary counts below, not raw entries
        summary_rows = [
            [hive_name.upper(), plugin_name, len(entries)]
            for hive_name, plugins in self.Plugin_Results.items()
            for plugin_name, entries in plugins.items()
        ]
        summary_df = pd.DataFrame(summary_rows, columns=["Hive", "Plugin", "Entries"])

        if self.CSV_MODE:
            summary_df.to_csv(self.OUTPUT_DIR.joinpath(f"{self.DESIGNATOR}_Plugins.csv"))

        print()
        t = df2table(summary_df, title="Plugin Results Summary")
        self.console.print(t)
        self._write_table(t=t, name="Plugins")

    def _get_meaningful_results(self):
        '''Function to extract only meaningful results'''
    
        df = self.results_df

        # Make Length DLP Margin
        #* Models Registry as a Normal Distribution to identify outliers in the data (potentially wrong model to use)
        if self.DLP:
            Data_SD =  df["Length"].std()
            Data_Mean =  df["Length"].mean()
            self.DLP_Margin = Data_Mean + (2*Data_SD)
        
        #* Determine if row has 'meaningful results' as set out in the LR    
        df["IS_MEANINGFUL"] = df.apply(self._is_row_meaningful,axis=1)
        
        #* Drop row if it doesn't
        df = df[df["IS_MEANINGFUL"] == True].copy()
        df = df.drop(columns=["IS_MEANINGFUL"])
        
        #* Convert Marks from FrozenSet to lists
        df["Marks"] = df.apply(lambda row: list(row["Marks"]) , axis=1)

        #* Rearrange columns so Hive is first
        cols = df.columns.tolist()
        cols = cols[-1:] + cols[:-1]
        df = df[cols]
        
        #* Store as pickle and CSV direct with pandas
        df.to_pickle(self.OUTPUT_DIR.joinpath(f"{self.DESIGNATOR}_Results.p"))
        
        if self.CSV_MODE:
            df.to_csv(self.OUTPUT_DIR.joinpath(f"{self.DESIGNATOR}_Results.csv"))

        #* Replace All NA values
        df = df.fillna("N/a")
        df["Value"] = df.apply(lambda row: "<BINARY_DATA>" if row["Value_Type"] == "REG_BINARY" else row["Value"], axis=1)

        
        if self.JSON_MODE:
            #* Do JSON ourselves as it seems to handle our data badly
            df_dict = df.to_dict(orient='records')

            with self.OUTPUT_DIR.joinpath(f"{self.DESIGNATOR}_Results.json").open("w") as f:
                json.dump(df_dict, f, cls=RegType_JSON_Serialiser)
        
        #* Convert to DF and print
        print()
        t = df2table(df,title="Alchemist Results")
        
        #* Call Print Directly on objects so _print formatting doesnt break stuff
        self.console.print(t)   
        self._write_table(t=t,name="Alchemist")         
    
    def _is_row_meaningful(self, row):
        #* Where Possible NA values exist, morph these into bool compatible values
        entropy = row["Entropy"] if not pd.isna(row["Entropy"]) else 0.0
        length = row["Length"] if  not pd.isna(row["Length"]) else 0
        marks = row["Marks"] if not pd.isna(row["Length"]) else []
        
        #! Not needed for Chi because we don't compare
        ChiSquared = row["ChiSquared"] 

        #* Find Margin
        MARGIN = self.DLP_Margin if hasattr(self,"DLP_Margin") else self.LENGTH_THRESHOLD
        
        #* Set Conditions and return
        MARK_CONDITION = len(marks) > 0
        LENGTH_CONDITION = length >= MARGIN
        ENTROPY_CONDITION = (entropy > self.SHANNON_THRESHOLD) and (not pd.isna(ChiSquared))
        
        CONDITIONS = [MARK_CONDITION,LENGTH_CONDITION,ENTROPY_CONDITION]
        
        is_meaningful = any(CONDITIONS)
        
        return is_meaningful


    def _add_analytics(self):
        '''Method to orchestrate adding of analysis columsn to the df'''
        
        results_df = pd.DataFrame()
        
        for hive_name in self.Extracted_Dict:
            with Status(f"Analyzing {hive_name}",console=self.console, spinner="weather"):
                hive_data = self.Extracted_Dict.get(hive_name)
                if len(hive_data) == 0:
                    continue
    
                #* Create DataFrame
                df = pd.DataFrame(hive_data)

                #* Create Entropy Metric (Works on REG_BINARY, REG_SZ (ALL VARIANTS))
                #? Tested using CyberChef to ensure it works as industry expected i.e. ensure parity
                df["Entropy"] = df.apply(self._calculate_entropy,axis=1)
                
                #* Create PhiSquared Metric (Works only on REG_BINARY )
                df["ChiSquared"] = df.apply(self._calculate_chi_squared,axis=1)
                
                #* Create Length Metric
                df["Length"] = df.apply(self._calculate_length,axis=1)
                
                #* Create Marks Metric   
                df["Marks"] = df.apply(self._find_marks,axis=1)   
                
                #* Assign Data Lineage Marker under "HIVE"
                df = df.assign(HIVE=hive_name.upper())

                #* Concat results in results_df                
                results_df = pd.concat([results_df, df], ignore_index=True)
        
        self.results_df = results_df

    def _calculate_entropy(self, row):
        """Calculate the Shannon Entropy of a registry value supports types : [REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ, REG_BINARY]"""
        value = row["Value"]
        vt = row["Value_Type"]
        
        if vt == "REG_BINARY":
            try:
                v = binascii.unhexlify(value)
                return self.__calculate_string_entropy(v)
            
            except:
                return self.__calculate_string_entropy(value)
            
        
        elif vt in ["REG_SZ","REG_EXPAND_SZ"]:
            return self.__calculate_string_entropy(value)
            
        elif vt == "REG_MULTI_SZ":
            if len(value) > 0:
                #* Average the Entropy over all strings
                return statistics.mean([self.__calculate_string_entropy(x) for x in value])
            else:
                return 0.0
        
        
        elif vt in ["REG_FILETIME","REG_DWORD_BIG_ENDIAN","REG_DWORD","REG_QWORD","REG_QWORD_BIG_ENDIAN","REG_NONE","REG_FULL_RESOURCE_DESCRIPTOR","REG_RESOURCE_REQUIREMENTS_LIST"]:
            return 0.0
        

    def __calculate_string_entropy(self, value):
        
        if isinstance(value,(str,bytes)):
            #* Occurance of each char in a string
            Data_Counter = Counter(value)

            #* Length of string
            Data_Len = len(value)
            
            Entropy = 0
            for char in Data_Counter.values():
                Probability = char / Data_Len
                Entropy -= Probability * math.log2(Probability)
                                                                
            return Entropy
        
        else:
            return 0.0
    
    def _calculate_chi_squared(self, row: Any):
        """Calculate the ChiSquared a registry value supports types : [REG_BINARY]"""
        value = row["Value"]
        vt = row["Value_Type"]
        
        if vt == "REG_BINARY":
            try:
                v = binascii.unhexlify(value)
                return self.__calculate_chi_squared(v)
            
            except:
                return self.__calculate_chi_squared(value)
        
        else:
            return pd.NA
        
    def __calculate_chi_squared(self, value):
        try:
            byte_count = Counter(value)
            total_bytes = len(value)
            
            if total_bytes < 256:
                #! Short values might skew the results, mark these as NA
                return pd.NA
            
            uniform_frequency = [total_bytes / 256] * 256
            observed_frequency = [byte_count.get(i,0) for i in range(256)]
            
            chi2_stat, p_value = chisquare(f_obs=observed_frequency, f_exp=uniform_frequency)
            
            if p_value < 0.05: #! Using Degrees of Freedom from (row-1) * (cols-1)
                return chi2_stat
            else:
                return pd.NA
            
        except TypeError:
            return pd.NA
            
    def _calculate_length(self, row: Any):
        """Calculate the ChiSquared a registry value supports types : [REG_BINARY]"""
        value = row["Value"]
        vt = row["Value_Type"]
        
        if vt == "REG_BINARY":
            try:
                v = binascii.unhexlify(value)
                return self.__calculate_length(v)
            
            except:
                return self.__calculate_length(value)
            
        elif vt in ["REG_SZ","REG_EXPAND_SZ"]:
            return (self.__calculate_length(value))
        
        elif vt in ["REG_MULTI_SZ"]:
            if len(value) > 0:
                return max([self.__calculate_length(x) for x in value if type(x) in [str,bytes,bytearray]])
            else:
                return pd.NA
        
        else:
            return pd.NA
        
    def __calculate_length(self, value):
        if isinstance(value, (str,bytes,bytearray)):
            return len(value)
        else:
            return pd.NA        

    def __discover_marks(self,text):
        if isinstance(text,bytes):
            try: 
                text = text.decode('utf-8')
            except Exception:
                return []
            
        elif isinstance(text, str):
            pass
        
        else:
            return []
        
        
        IP_PATTERN = re.compile(r'^\b(?:\d{1,3}[\._]){3}\d{1,3}\b$')
        URL_PATTERN = re.compile(r'^https?://\S+|www\.\S+$')
        B64_PATTERN = re.compile(r'[A-Za-z0-9+/=]{33,}')
    
        Discovered_Marks = []
        try:
                
            # Check for IP addresses
            if IP_PATTERN.search(text):
                try:
                    #* Sometimes IP use _ instead of . when storing, we catch this in the regex but need to change it in post processing
                    text = text.replace("_",".")
                    ip = ip_address(text)
                    #* Ignore Private/Reserved IP Space
                    if ip.is_global:
                        Discovered_Marks.append('IP')
                    else:
                        self._print(f"'{ip}' is not a global address",level="DEBUG")
                except:
                    pass
                
            # Check for URLs
            if URL_PATTERN.search(text):
                try:
                    url = tldextract.extract(text)
                    #* if the URL is a Microsoft owned one or it has no suffix (is internally routed i.e. HTTP://HOSTNAME) ignore it
                    if url.domain.lower() in ["microsoft","skype","live","windows","bing","hotmail","outlook"] or url.suffix == "":
                        self._print(f"'{text}' is either Microsoft-owned or likely invalid",level="DEBUG")
                    else:
                        Discovered_Marks.append('URL')
        
                except Exception as e:
                    pass
                
                
            # Check for Base64-encoded strings
            for match in B64_PATTERN.findall(text):
                try:
                    decoded = base64.b64decode(match, validate=True)
                    if decoded.decode('utf-8').isascii():
                        Discovered_Marks.append('Base64')
                        break  # Only add 'Base64' once per text
                
                except Exception as e:
                    continue
                
            return Discovered_Marks
        
        except Exception as e:
            self._print(f"Issue occurred while discovering marks: {e}",level="DEBUG")
            return []
    
    def _find_asep(self):
        '''ASEP scan using values already extracted for statistical analysis'''
        df = self.results_df[["Key_Path","Value_Name","Value","TS"]]
        data = df.to_dict(orient='records')

        self._report_asep(self._build_asep_vectors(data))

    def _find_asep_targeted(self):
        '''ASEP scan that queries only the known ASEP locations directly via regipy,
        instead of extracting every key/value in the hive first. Used when persistence
        is the only mode running, so the full extraction pass can be skipped entirely'''
        self._print("Persistence-only mode: querying known ASEP locations directly, skipping full key/value extraction")

        records = []

        #* Build the full list of (hive, key_path, is_subtree) lookups so progress can be shown per-location
        jobs = []
        for hive_name in self.REGISTRY.get_added_hives():
            hive = self.REGISTRY.get_hive(hive_name)
            if not hive:
                continue

            #* Single-value autorun keys - read directly, no need to recurse
            jobs.extend((hive_name, hive, key_path, False) for key_path in self.ASEP_RUNKEYS)

            #* Scheduled tasks / services live under subtrees, so scope the recursion to just those
            jobs.extend((hive_name, hive, prefix, True) for prefix in self.ASEP_SUBTREE_PREFIXES)

        progress_columns = (
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
        )

        with Progress(*progress_columns, console=self.console) as progress:
            task = progress.add_task(self._format_message("Scanning ASEP locations"), total=len(jobs))

            for hive_name, hive, key_path, is_subtree in jobs:
                if is_subtree:
                    records.extend(self._read_subtree_values(hive, key_path))
                else:
                    records.extend(self._read_key_values(hive, key_path))

                progress.advance(task)

        if self.DROP_UNKNOWN:
            records = [record for record in records if not record["Value_Type"].isdigit()]

        self._print(f"Discovered {len(records)} ASEP-relevant value(s) via targeted lookups")

        self._report_asep(self._build_asep_vectors(records))

    def _read_key_values(self, hive, key_path):
        '''Reads the values directly under a single known registry key, without recursing'''
        try:
            subkey = hive.get_key(key_path)
        except (RegistryKeyNotFoundException, NoRegistrySubkeysException):
            return []

        ts = convert_wintime(subkey.header.last_modified).strftime("%Y-%m-%d %H:%M:%S")

        return [
            {"Key_Path" : key_path, "Value_Name" : value.name, "Value_Type" : str(value.value_type), "Value" : value.value, "TS" : ts}
            for value in subkey.iter_values()
        ]

    def _read_subtree_values(self, hive, key_path):
        '''Recurses only the given subtree instead of walking the whole hive'''
        try:
            subkey = hive.get_key(key_path)
        except (RegistryKeyNotFoundException, NoRegistrySubkeysException):
            return []

        return [
            {"Key_Path" : entry.path, "Value_Name" : value.name, "Value_Type" : str(value.value_type), "Value" : value.value, "TS" : entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")}
            for entry in hive.recurse_subkeys(nk_record=subkey, path_root=key_path)
            for value in entry.values
        ]

    def _build_asep_vectors(self, data):
        '''Matches extracted Key_Path/Value_Name/Value records against known ASEP locations'''
        ASEP_Vectors = []

        #* Group sibling values by key path so services/tasks can be enriched with more than one field
        values_by_path = {}
        for record in data:
            values_by_path.setdefault(record["Key_Path"], {})[record["Value_Name"]] = record["Value"]

        for record in data:
            #* Try and Find Scheduled Tasks and their associated ID
            if record["Key_Path"].startswith(self.ASEP_SCHEDULED_TASK_PREFIX) and record["Value_Name"] == "Id":
                Name = record["Key_Path"].split("\\")[-1]
                ID = record["Value"]
                task_details = values_by_path.get(f"{self.ASEP_SCHEDULED_TASK_DETAILS_PREFIX}\\{ID}", {})
                Context = self._format_task_context(ID, task_details)
                ASEP_Vectors.append(["SCHEDULED_TASK",Name,Context,record["TS"],record["Key_Path"]])

            #* Try and find HKLM bound services
            elif record["Key_Path"].startswith(self.ASEP_HKLM_SERVICE_PREFIX) and record["Value_Name"] == "DisplayName":
                Name = record["Key_Path"].split("\\")[-1]
                Context = self._format_service_context(record["Value"], values_by_path.get(record["Key_Path"], {}))
                ASEP_Vectors.append(["HKLM_SERVICE",Name,Context,record["TS"],record["Key_Path"]])

            #* Try and find HKCU bound services
            elif record["Key_Path"].startswith(self.ASEP_HKCU_SERVICE_PREFIX) and record["Value_Name"] == "DisplayName":
                Name = record["Key_Path"].split("\\")[-1]
                Context = self._format_service_context(record["Value"], values_by_path.get(record["Key_Path"], {}))
                ASEP_Vectors.append(["HKCU_SERVICE",Name,Context,record["TS"],record["Key_Path"]])

            elif record["Key_Path"] in self.ASEP_RUNKEYS:
                ASEP_Vectors.append(["AUTORUNS",record["Value"],record["Value_Name"],record["TS"],record["Key_Path"]])

        return ASEP_Vectors

    def _format_service_context(self, display_name, service_values):
        '''Builds a structured (JSON-serializable) summary of a service's most relevant registry values'''
        context = {}

        start = service_values.get("Start")
        if start is not None:
            try:
                start = self.SERVICE_START_TYPES.get(int(start), start)
            except (TypeError, ValueError):
                pass
            context["start"] = start

        account = service_values.get("ObjectName")
        if account:
            context["account"] = account

        image_path = service_values.get("ImagePath")
        if image_path:
            context["Image"] = image_path

        context["value"] = display_name

        return context

    def _format_task_context(self, task_id, task_values):
        '''Builds a structured (JSON-serializable) summary of a scheduled task using its TaskCache\\Tasks details'''
        context = {}

        path = task_values.get("Path")
        if path:
            context["path"] = path

        context["value"] = task_id

        return context

    def _report_asep(self, ASEP_Vectors):
        '''Writes the discovered ASEP vectors to CSV/JSON and prints/persists the results table'''
        asep_df = pd.DataFrame(columns=["ASEP Vector","Value","Context","Key Written","Location"],data=ASEP_Vectors)

        #* Location is opt-in via --show-locations, regardless of which scan mode is running
        if not self.SHOW_LOCATIONS:
            asep_df = asep_df.drop(columns=["Location"])

        if self.CSV_MODE:
            asep_df.to_csv(self.OUTPUT_DIR.joinpath(f"{self.DESIGNATOR}_ASEP_Results.csv"))

        if self.JSON_MODE:
            asep_df.to_json(self.OUTPUT_DIR.joinpath(f"{self.DESIGNATOR}_ASEP_Results.json"),orient="records")

        print()
        t = df2table(asep_df,title="ASEP Keys")
        self.console.print(t)
        self._write_table(t=t,name="ASEP")

    def _find_marks(self, row):
        '''Function to find 'Marks' of interesting artefacts, including IPs,URLs,B64 text'''
        value = row["Value"]
        vt = row["Value_Type"]
        kp = row["Key_Path"]
        Marks = []
        
        if vt in ["REG_SZ","REG_EXPAND_SZ"]:
            Marks.extend(self.__discover_marks(value))
        
        elif vt in ["REG_MULTI_SZ"]:
            results = [self.__discover_marks(x) for x in value]
            Marks.extend([item for sublist in results for item in sublist])
        
        elif vt == "REG_BINARY":
            try:
                v = binascii.unhexlify(value)
                Marks.extend(self.__discover_marks(v))
            
            except:
                Marks.extend(self.__discover_marks(value))
            
        else:
            #* No Scanning for Alternative Values (Only str/strlike)
            pass
        
        return frozenset(Marks)

if __name__ == "__main__":
    console = Console()

    #* Arguments shared by every scan mode
    common = argparse.ArgumentParser(add_help=False)

    #* Required Arguments
    common.add_argument("-d", "--directory", type=Path, help="Specify the directory where registry files are stored", required=True, metavar = "PATH")

    #* Processing Flags
    common.add_argument("--restore-hives", action="store_true", help="Replay Registry Transaction Logs into Hives Where Possible")
    common.add_argument("--drop-unknown-reg-types", action="store_true", help="Drop values with an unrecognized registry type",default=True)

    #* Output flags
    common.add_argument("--format",choices=["JSON","CSV","ALL"],action="store",type=str.upper,help="Enable JSON or CSV for output formats",default="JSON")
    common.add_argument("--show-locations",action="store_true",help="Include the registry key location/path as a column in output")

    #* Baseline Arguments
    common.add_argument("--collect-baseline",action="store_true",help="Dumps Extracted Values JSON & Pickle to Deduplicate Against")
    common.add_argument("--use-baseline",action="store",type=Path,help="Uses Extracted Values JSON/Pickle file to Deduplicate Against")

    #* Statistical Analysis Thresholds and Flags
    common.add_argument("--shannon_threshold",type=float,action="store")
    common.add_argument("--length_threshold",type=float,action="store")
    common.add_argument("--dynamic-length-purging",action="store_true")

    #* Plugin Arguments (only meaningful in "plugins" mode)
    common.add_argument("--plugins", action="store", type=str, help="Comma-separated regipy plugin names to run (default: all validated plugins)")
    common.add_argument("--include-unvalidated-plugins", action="store_true", help="Also run regipy plugins without validation test cases")

    #* Extra Arguments
    common.add_argument("--verbose", "-v", action="count", default=0, help="Increase logging verbosity, e.g. -v enables DEBUG logging")
    common.add_argument("--name", "-n", action="store", type=lambda x : x.strip(),help="Assign a designator to a scan, all saved files used this to identify multiple runs")

    parser = argparse.ArgumentParser(prog="FADED ALCHEMIST", description="Capability to enable detection of malware-induced Windows Registry modifications")

    #* Scan Types - each mode is its own subcommand, exactly one is run per invocation
    subparsers = parser.add_subparsers(dest="mode", required=True, help="Scan mode to run")
    subparsers.add_parser("comprehensive", parents=[common], help="Perform ALL Available Analysis")
    subparsers.add_parser("persistence", parents=[common], help="Discover Persistence on Device via the Registry")
    subparsers.add_parser("artefacts", parents=[common], help="Perform Statistical Analysis of the Registry")
    subparsers.add_parser("plugins", parents=[common], help="Run regipy's built-in artefact plugins against each hive")
    subparsers.add_parser("list-plugins", help="List all available regipy plugins and exit")

    args = parser.parse_args()

    if args.mode == "list-plugins":
        table = Table(title=f"Available regipy Plugins ({len(PLUGINS)})")
        table.add_column("Name")
        table.add_column("Compatible Hive")
        table.add_column("Description")
        for plugin in sorted(PLUGINS, key=lambda p: p.NAME or ""):
            table.add_row(plugin.NAME, plugin.COMPATIBLE_HIVE.upper(), plugin.DESCRIPTION)
        console.print(table)
        raise SystemExit(0)

    #* Translate the chosen mode into the flags the rest of the tool expects
    args.persistence = args.mode in ("comprehensive", "persistence")
    args.artefacts = args.mode in ("comprehensive", "artefacts")

    #* --format is the single source of truth for output mode
    args.json = False
    args.csv = False

    match args.format:
        case "JSON":
            args.json = True

        case "CSV":
            args.csv = True

        case "ALL":
            args.json, args.csv = True,True

    ACCEPTED_BASELINE_SUFFIXS = [".p",".pickle",".json"]

    if args.use_baseline:
        if args.use_baseline.suffix.lower() not in ACCEPTED_BASELINE_SUFFIXS:
            parser.error(f"Invalid baseline extension '{args.use_baseline.suffix}' : accepted {ACCEPTED_BASELINE_SUFFIXS}")

    Alchemist(args=args,console=console)
