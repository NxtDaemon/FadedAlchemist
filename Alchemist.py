import argparse
import base64
import binascii
import json
import math
import pickle
import re
import statistics
import time
from collections import Counter
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Any

import pandas as pd
from regipy import RegistryHive
from regipy.recovery import apply_transaction_logs
from regipy.structs import VALUE_TYPE_ENUM
from rich import inspect
from rich.console import Console
from rich.status import Status
from rich.table import Table
from scipy.stats import chisquare
import tldextract

pd.set_option('display.max_rows', None)
pd.set_option('future.no_silent_downcasting', True)

def df2table(df,title=""):
    #* Create Rich.Table and Populate with Results
    t = Table(title=title)

    #* Add Columns        
    for col in df.columns:
        t.add_column(col)
        
    #* Add Rows
    for index, row in df.iterrows():
        t.add_row(*[str(val) for val in row])
    
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
    
    def add_hive(self, hive : RegistryHive):
        """Method to add Add to Collection"""
        self.hives.update({hive.hive_type : hive})
        
    def get_added_hives_u(self):
        """Method to return all hives in UPPERCASE"""
        return [hive.upper() for hive in self.hives]
        
    def get_added_hives(self):    
        """Method to return all hives in UPPERCASE"""
        return [hive for hive in self.hives]

class Alchemist():
    TOOL_CONSOLE_PROMPT = "[ FADED ALCHEMIST :crystal_ball::test_tube: ]"
    
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

    
    def __init__(self, args : dict, console : Console = Console()):
        self.console = console
        
        self.registry_files = args.directory
        self.DEBUG_MODE = args.verbose
        self.DESIGNATOR = args.name
        
        self.CSV_MODE = args.csv
        self.JSON_MODE = args.json
        
        self._print(f"[ :toolbox: ] OUTPUT MODE : '{args.format}'")
        
        
        if self.DESIGNATOR:
            self._print(f"[ :briefcase: ] Assigned Designator '{self.DESIGNATOR}'")
            self.OUTPUT_DIR = Path().joinpath(self.DESIGNATOR) 

            if not self.OUTPUT_DIR.exists():
                self.OUTPUT_DIR.mkdir()
                self._print(f"[ :briefcase: ] Created Output Directory '{self.OUTPUT_DIR}'")
            else:
                self._print(f"[ :briefcase: ] Using Output Directory '{self.OUTPUT_DIR}'")

        else:
            self.OUTPUT_DIR = Path()
            self._print(f"[ :briefcase: ] Using Output Directory '{self.OUTPUT_DIR}'")
                    
        #* Baseline Args
        self.COLLECT_BASELINE = args.collect_baseline
        self.Baseline_Data = args.use_baseline
        
        #* Processing Args
        self.DROP_UNKNOWN = args.drop_unknown_reg_types
        self.DLP = args.dynamic_length_purging
        self.SHANNON_THRESHOLD = args.shannon_threshold or 5.7
        self.LENGTH_THRESHOLD = args.length_threshold or 4096
        self.asep = args.persistence
    
        #* Collect Registry Files
        self._resolve_registry_files()
        
        collected_hives = self.REGISTRY.get_added_hives_u()
    
        self._print(f"[ :arrows_counterclockwise: ] Loaded {len(collected_hives)} Hives : {collected_hives}")
    
        #* Start timer and start hive value extraction
        T1 = datetime.now()
        self._extract_values_from_hives()
        
        #* If Baseline Data is detected remove all baseline data
        if self.Baseline_Data:
            self._eliminate_baseline()
        
        # if True:
        #     with open("gootloader_proc.json","r") as f:
        #         self.Extracted_Dict = json.load(f)
        #         self._print("Loaded ProcData")
        
        # if True:
        #     with open("Proc_Data2.json","w") as f:
        #         json.dump(self.Extracted_Dict,f,cls=RegType_JSON_Serialiser)
        #         self._print("Saved ProcData")
        
        T2 = datetime.now()
        self._print(f"[ :alarm_clock: ] Finished Processing Device in : {T2 - T1}")
                    
        self._add_analytics()
        
        if self.asep:
            self._find_asep()
        
        T3 = datetime.now()
        self._print(f"[ :alarm_clock: ] Finished Analzysing Device in : {T3 - T2}")
        
        self._get_meaningful_results()
        
        
    def _write_table(self,t,name):
        with self.OUTPUT_DIR.joinpath(f"{name}.table").open("wt") as report_file:
            console = Console(file=report_file,width=700)
            console.rule(f"Writing {name} Table - {datetime.now().ctime()}")
            console.print(t)
                
    def _print(self,message : str, debug: bool = False):
        """Method to print to the console via rich"""
                
        if debug:
            if self.DEBUG_MODE:
                self.console.print(f"{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} {self.TOOL_CONSOLE_PROMPT} [DEBUG] - {message}")
        else:
            self.console.print(f"{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} {self.TOOL_CONSOLE_PROMPT} - {message}")        

    def _eliminate_baseline(self):
        """Method to remove previously seen data (Baseline data) from the Extracted_Dict"""
        self._print(f"[ :bookmark: ] Reading Baseline from '{self.Baseline_Data.resolve()}'")
        
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
        self._print(f"[ :bookmark_tabs: ] Read {Total_Records} Baseline Records : {Baseline_Records_Summary}")
        
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
            
            self._print(f"[ :axe: ] Removed {Record_Delta} Baseline Records From '{hive_name.upper()}' - {End_Amount_Of_Records} Remaining")
            self.Extracted_Dict.update({hive_name : Deduplicated_Data})   
            
        self._print(f"[ :toolbox: ] Removed {Total_Records_Removed} Baseline Records")
        
        Data_Reduction_Percentage = (Total_Records_Removed / self.total_records_extracted) * 100
        self._print(f"[ :toolbox: ] Total Data Reduction - {Data_Reduction_Percentage:.2f}%")

    def _extract_values_from_hives(self):
        """Method to kickoff analysis of all hives"""
        hives_names = self.REGISTRY.get_added_hives()
        values_extracted = 0
        
        with Status("[bold green] Processing", spinner="earth",console=self.console) as status:
                    
            for hive_name in hives_names:
                hive = self.REGISTRY.get_hive(hive_name)
                if not hive:
                    continue 
                
                status.update(f"[ :fire: ] Starting Extraction of '{hive.hive_type.upper()}'")
                
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
                self._print(f"[ :tractor: ] Extracted {len(extracted_values)} out of '{hive_name.upper()}'")
                
                self.Extracted_Dict[hive_name] = extracted_values
            
            self._print(f"[ :toolbox: ] Extracted {values_extracted} Total Values")
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

        self._print(f"[ :magnifying_glass_tilted_right: ] Discovered {len(HIVES)} Hives : {[f.name for f in HIVES]}")
        
        with console.status("Resolving Registry Hives", spinner="moon"):
            for HIVE in HIVES:
                time.sleep(0.1)

                h = RegistryHive(HIVE)
                
                if (h.header.primary_sequence_num != h.header.secondary_sequence_num):
                    #* If the hive is dirty then lets discover the LOG files for this
                    self._print(f"[ :soap: ] Dirty '{HIVE.name}' Hive Detected : [1st {h.header.primary_sequence_num} <!> 2nd {h.header.secondary_sequence_num}]")
                     
                    #* Search for only LOG1 and LOG2 files of the same name in the same directory 
                    LOGS = list(HIVE.parent.rglob(f"*{HIVE.name}.LOG[12]"))
                    self._print(f"Discovered {len(LOGS)} Transaction Logs for {HIVE.name} : {[f.name for f in LOGS]}",debug=True)

                    #* Assign only the correct logs to the right variable and ensure that the file is actually populated as Regipy doesnt check for this
                
                    primary_log = [f for f in LOGS if f.suffix == ".LOG1" and f.stat().st_size > 0]
                    primary_log = primary_log[0] if primary_log else None
                    
                    secondary_log = [f for f in LOGS if f.suffix == ".LOG2" and f.stat().st_size > 0] or None
                    secondary_log = secondary_log[0] if secondary_log else None
                    
                    self._print(f"Valid Transaction Logs for {HIVE.name} : {[x.name for x in [primary_log,secondary_log] if x != None]}",debug=True)
                    
                    #* Create a restored hive by applying transaction logs onto the hive
                    restored_hive, dirty_hive_count = apply_transaction_logs(HIVE,primary_log_path=primary_log,secondary_log_path=secondary_log,verbose=True)
                    self._print(f"[ :magnet: ] Replayed {dirty_hive_count} Transactions into '{HIVE.name}'")
                    try:
                        h = RegistryHive(restored_hive)
                        self.REGISTRY.add_hive(h)
                    except:
                        self.REGISTRY.add_hive(h)
                                    
                else:
                    self.REGISTRY.add_hive(h)
                    self._print(f"[ :white_heavy_check_mark: ] Hive '{HIVE.name}' Passed All Checks")

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
                        self._print(f"{ip} is not Global",debug=True)
                except:
                    pass
                
            # Check for URLs
            if URL_PATTERN.search(text):
                try:
                    url = tldextract.extract(text)
                    #* if the URL is a Microsoft owned one or it has no suffix (is internally routed i.e. HTTP://HOSTNAME) ignore it
                    if url.domain.lower() in ["microsoft","skype","live","windows","bing","hotmail","outlook"] or url.suffix == "":
                        self._print(f"{text} is either owned by Microsoft or likely invalid",debug=True)
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
            self._print(f"Issue Occured within Discovered Marks - {e}",debug=True)
            return []
    
    def _find_asep(self):
        df = self.results_df[["Key_Path","Value_Name","Value"]]
        data = df.to_dict(orient='records')
        
        #* Has removed SOFTWARE/SYSTEM etc as this isn't loaded into an actual registry and those paths wont resolve correctly
        ASEP_RUNKEYS = {
            '\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit', 
            '\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run', 
            '\\Wow6432Npde\\Microsoft\\Windows\\CurrentVersion\\RunOnce', 
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
        SCHEDULED_TASK_NAME_START = r"\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
        HKCU_SERVICE_START = r"\Microsoft\Windows NT\CurrentVersion\Services"
        HKLM_SYSTEM_SERVICE_START = r"\ControlSet001\Services"
        ASEP_Vectors = []
        
        #* Try and Find Scheduled Task in Differential Data
        for record in data:
            #* Try and Find Scheduled Tasks and their associated ID
            if record["Key_Path"].startswith(SCHEDULED_TASK_NAME_START) and record["Value_Name"] == "Id":
                Name = record["Key_Path"].split("\\")[-1]
                ID = record["Value"]
                ASEP_Vectors.append(["SCHEDULED_TASK",Name,ID])
                
            #* Try and find HKLM bound services 
            elif record["Key_Path"].startswith(HKLM_SYSTEM_SERVICE_START) and record["Value_Name"] == "DisplayName":
                Name = record["Key_Path"].split("\\")[-1]
                DisplayName = record["Value"]
                ASEP_Vectors.append(["HKLM_SERVICE",Name,DisplayName])
                
            #* Try and find HKCU bound services
            elif record["Key_Path"].startswith(HKCU_SERVICE_START) and record["Value_Name"] == "DisplayName":
                Name = record["Key_Path"].split("\\")[-1]
                DisplayName = record["Value"]
                ASEP_Vectors.append(["HKCU_SERVICE",Name,DisplayName])
                
            elif record["Key_Path"] in ASEP_RUNKEYS:
                ASEP_Vectors.append(["AUTORUNS",record["Value"],record["Value_Name"]])
        
        asep_df = pd.DataFrame(columns=["Method","Value","Context"],data=ASEP_Vectors)
        
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

    parser = argparse.ArgumentParser(prog="FADED ALCHEMIST", description="Capability to enable detection of malware-induced Windows Registry modifications")

    #* Required Arguments    
    parser.add_argument("--directory", "-D", type=Path, help="Specify the directory where registry files are stored", required=True)
    
    #* Processing Flags 
    parser.add_argument("--restore_hives", action="store_true", help="Replay Registry Transaction Logs into Hives Where Possible",default=True)
    parser.add_argument("--merge_dfs", action="store_true", help="Merge All Results in one DataFrame Instead of Per-Hive",default=True)
    parser.add_argument("--drop_unknown_reg_types", action="store_true", help="Merge All Results in one DataFrame Instead of Per-Hive",default=True)
    
    #* Output flags
    parser.add_argument("--format",choices=["JSON","CSV","ALL"],action="store",help="Enable JSON or CSV for output formats",default="JSON")
    parser.add_argument("--csv",action="store_true",help="Enable CSV Mode for Output")
    parser.add_argument("--json",action="store_true",help="Enable JSON Mode for Output")
    
    #* Baseline Arguments
    parser.add_argument("--collect-baseline",action="store_true",help="Dumps Extracted Values JSON & Pickle to Deduplicate Against")
    parser.add_argument("--use-baseline",action="store",type=Path,help="Uses Extracted Values JSON/Pickle file to Deduplicate Against")
    
    #* Scan Types
    parser.add_argument("--comprehensive", "-c", action="store_true", help="Perform ALL Available Analysis")
    parser.add_argument("--persistence", "-p", action="store_true", help="Discover Persistence on Device via the Registry")    
    parser.add_argument("--artefacts", "-art", action="store_true", help="Perform Statistical Analysis of the Registry")

    #! Scan Type - Not Implemented (Out of Scope)
    # parser.add_argument("--mru", "-m", action="store_true", help="Discover MRU Objects in the Registry")    

    #* Statistical Analysis Thresholds and Flags
    parser.add_argument("--shannon_threshold",type=float,action="store")
    parser.add_argument("--length_threshold",type=float,action="store")
    parser.add_argument("--dynamic-length-purging",action="store_true")
    
    #* Extra Arguments 
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging (i.e Enable DEBUG Mode)")
    parser.add_argument("--name", "-n", action="store", type=lambda x : x.strip(),help="Assign a designator to a scan, all saved files used this to identify multiple runs")
    
    args = parser.parse_args()
    
    if args.comprehensive:
        args.artefacts = True
        args.persistence = True
        args.mru = True 
    
    match args.format:
        case "JSON":
            args.json = True
        
        case "CSV":
            args.csv = True
        
        case "ALL":
            args.json, args.csv = True,True
    
    ACCEPT_BASELINE_SUFFIX = [".p",".pickle",".json"]
    
    if args.use_baseline:
        if args.use_baseline.suffix.lower() not in ACCEPT_BASELINE_SUFFIX:
            console.print(f"[ :loudspeaker: ] ERROR - Invalid Baseline Extension '{args.use_baseline.suffix}' : Accepted {ACCEPT_BASELINE_SUFFIX} ")
            exit()
    
    Alchemist(args=args,console=console)
