import csv
import json
import os
import shutil
import time
from datetime import date
from collections import defaultdict

import mitreattack.attackToExcel.attackToExcel as attackToExcel
import mitreattack.attackToExcel.stixToDf as stixToDf
import nvdlib
import pandas as pd
from cwe2.database import Database
from git import InvalidGitRepositoryError, Repo
from stix2 import Filter


class cve_custom_encoder(json.JSONEncoder):
    def default(self, o):
        return o.__dict__


db = Database()
filt = Filter('type', '=', 'attack-pattern')
fs = None


def get_formatted_runtime(start, end):
    hours, rem = divmod(end - start, 3600)
    minutes, seconds = divmod(rem, 60)
    return "{:0>2}h {:0>2}m and {:05.2f}s".format(int(hours), int(minutes), seconds)


def get_attack_pattern_by_capec_id(src, capec_id):
    filt = [
        Filter('type', '=', 'attack-pattern'),
        Filter('external_references.external_id', '=', 'CAPEC-' + capec_id),
        Filter('external_references.source_name', '=', 'capec'),
    ]
    return src.query(filt)


def get_capec_external_references_cwes(src, capec):
    id = capec.split("-")[1]
    all_refs = get_attack_pattern_by_capec_id(src, id)
    if len(all_refs) != 0:
        return all_refs[0]["external_references"]
    else:
        return []

def iterate_cve_for_given_cwe(db, cwe):
    cve_list = []
    weakness = db.get(cwe.split("-")[1])
    observed_examples = weakness.__dict__["observed_examples"]
    cves = [word for word in observed_examples.split(":") if word.startswith("CVE-")]
    print(f"Found {len(cves)} CVE's for CWE {cwe}: ")
    cve_num = 0
    for cve in cves:
        print(f"({cve_num+1}/{len(cves)}) ", end='')
        cve_num += 1
        print(cve, end=', ')
        cve_list.append(cve)
        #cve_list.append(get_cve_info(cve)) # Uncomment this line to get full CVE info
    return {"cwe": cwe, 
            "cves": cve_list,
            #"cwe_info": weakness.__dict__  # Uncomment this line to get full CWE info
            }


def pull_clone_gitrepo(directory, repo):
    if not os.path.isdir(directory):
        Repo.clone_from(repo, directory)
    else:
        try:
            repo = Repo(directory)
            repo.remotes.origin.pull()
        except InvalidGitRepositoryError:
            shutil.rmtree(directory)
            Repo.clone_from(repo, directory)


def generate_techniques_dataframe():
    attackdata = attackToExcel.get_stix_data("enterprise-attack", "v4.0")
    # get Pandas DataFrames for techniques, associated relationships, and citations
    techniques_data = stixToDf.techniquesToDf(attackdata, "enterprise-attack")
    return techniques_data["techniques"]


def get_grouped_o_cloud_technique(file, drop_duplicates: bool = False):
    # Extract CAPEC's for our selected O-Cloud threats and return them.
    o_cloud = pd.read_csv(file, sep=';', index_col=0)
    if drop_duplicates:
        o_cloud = o_cloud.drop_duplicates(subset=["Technique"])
    return o_cloud.groupby("Name")


def get_technique_capecs_id(grouped, techniques_df):
    techniques_capecs = []
    for s, group in grouped:
        for i in group["Technique"].drop_duplicates():
            capecs = []
            for capec in techniques_df[techniques_df["ID"].str.contains(i)]["CAPEC ID"]:
                try:
                    float(capec)
                except:
                    for c in capec.split(", "):
                        capecs.append(c)
            techniques_capecs.append((i, capecs))
    return techniques_capecs

def get_technique_capecs_id_custom(techniques, directory):
    grouped_results = defaultdict(list)
    capec21_dir = os.path.join(directory, "capec/2.1/attack-pattern")
    enterprise_attack_dir = os.path.join(directory, "enterprise-attack/attack-pattern")
    attack_pattern_dirs = [capec21_dir, enterprise_attack_dir]
    if not os.path.isdir(capec21_dir) or not os.path.isdir(enterprise_attack_dir):
        raise FileNotFoundError(f"Directory not found: {capec21_dir} or {enterprise_attack_dir}")

    # Iterate through JSON files in the directory
    file_number = 0
    for attack_pattern_dir in attack_pattern_dirs:
        for filename in os.listdir(attack_pattern_dir):
            file_number += 1
            if filename.endswith(".json"):
                file_path = os.path.join(attack_pattern_dir, filename)
                
                # Load and parse JSON file
                with open(file_path, 'r', encoding='utf-8') as f:
                    stix_data = json.load(f)
                
                # Process each object in the JSON
                for obj in stix_data.get("objects", []):
                    if obj.get("type") == "attack-pattern" and "external_references" in obj:
                        for ref in obj["external_references"]:
                            try:
                                if (ref.get("external_id") in techniques):# or (ref.get("external_id").split(".")[0] in techniques): # uncomment this line to include subtechniques
                                    # Extract CAPECs associated with the technique
                                    for capec_ref in obj["external_references"]:
                                        if capec_ref.get("source_name") == "capec":
                                            if ref.get("external_id") in techniques:
                                                grouped_results[ref.get("external_id")].append(capec_ref["external_id"])
                                            else:
                                                grouped_results[ref.get("external_id").split(".")[0]].append(capec_ref["external_id"])
                            except:
                                pass
    print(f"Processed {file_number} files.")
    return [(technique_id, grouped_results.get(technique_id, [])) for technique_id in techniques]



def write_ids_to_file(techniques_capecs, file):
    f = open(file, 'w')
    writer = csv.writer(f)
    writer.writerow(['Technique ID', 'CAPEC ID'])

    for t_name, capec_ids in techniques_capecs:
        if len(capec_ids) != 0:
            for id in capec_ids:
                writer.writerow([t_name, id])
    f.close()


def print_capec_stats(techniques_capecs):
    count_capecs = 0
    count_techniques = 0
    count_non_empty_techniques = 0
    unique_capecs = set()
    for (t, l_capec) in techniques_capecs:
        len_l = len(l_capec)
        count_techniques += 1
        count_capecs += len_l
        if len_l != 0:
            count_non_empty_techniques += 1
        for c in l_capec:
            unique_capecs.add(c)

    print(f"Techniques: {count_techniques}")
    print(f"Non-Empty Techniques: {count_non_empty_techniques}")
    print(f"CAPECs: {count_capecs}")
    print(f"Unique CAPECs: {len(unique_capecs)}")

def print_cwe_stats(t_cwe_cve_dict):
    count_cwes = 0
    count_cves = 0
    unique_cwes = set()
    unique_cves = set()
    for t in t_cwe_cve_dict["data"]:
        for c in t["t_findings"]:
            for f in c["c_findings"]:
                count_cwes += 1
                count_cves += len(f["cves"])
                unique_cwes.add(f["cwe"])
                unique_cves.add(f["cves"])
    print(f"CWE's: {count_cwes}")
    print(f"Unique CWE's: {len(unique_cwes)}")
    print(f"CVE's: {count_cves}")
    print(f"Unique CVE's: {len(unique_cves)}")
    
def find_cwe_for_capec(start, techniques_capecs, fs):
    capec_list = []
    list_of_tinfos = []
    print("Start fetching CAPEC'S -> CWE'S -> CVE'S for given CAPEC-IDS...")
    for t_id, capec_ids in techniques_capecs:
        if len(capec_ids) != 0:
            capec_list = []
            for c_id in capec_ids:
                print(f"\nSearching CWE's for {c_id}")
                findings = []
                for reference in get_capec_external_references_cwes(fs, c_id):
                    if reference["source_name"] == "cwe":
                        print("Found: ", reference["external_id"])
                        #findings.append(reference["external_id"]) # Uncomment this line to only get CWE's, no CVE's
                        findings.append(iterate_cve_for_given_cwe(db, reference["external_id"]))
                capec_list.append({"capec_id": c_id, "c_findings": findings})
                print("\n")
        list_of_tinfos.append({"technique_id": t_id, "t_findings": capec_list})
    end = time.time()
    print(f"Finished in {get_formatted_runtime(start, end)}.")
    return {
        "scan_date": f"{date.today()}",
        "scan_runtime": get_formatted_runtime(start, end),
        "data": list_of_tinfos
    }


def write_dict_to_file(t_cwe_cve_dict, file):
    with open(file, "w") as outfile:
        json.dump(t_cwe_cve_dict, outfile, cls=cve_custom_encoder)

def get_cve_info(cve):
    print(f"Getting info for {cve}, ", end='')
    # cve_full = None
    # while cve_full is None:
    #     try:
    #         cve_full = cve_lookup.cve(cve)
    #         print(f"{cve_full.id}, ", end='')
    #     except Exception as e:
    #         print(f"\nError during lookup for cve entry ..\n -> {e} \n Retrying.\n")
    #         time.sleep(3)

    r = None
    while r is None:
        try:
            r = nvdlib.searchCVE(cveId=cve, 
                                key='31cde13c-0ee0-4b1b-81b3-4214d453e608',
                                delay=0.6
                                )[0]
            if r is not None:
                return ({           #"id": cve_full.id,
                                    "cve_id": cve,
                                    "score": r.score,
                                    "v2_score": r.v2score,
                                    "v2_exploitability_score": r.v2exploitability,
                                    "v2_impact_score": r.v2impactScore,
                                    "v2_vector": r.v2vector,
                                    "access_vector": r.metrics.cvssMetricV2[0].cvssData.accessVector,
                                    "full_metrics": r.metrics.cvssMetricV2,
                                    "description": r.descriptions[0].value,
                                    "cpe_vulnerable": r.cpe[0].vulnerable,
                                    "cpe_criteria": r.cpe[0].criteria,
                                    "published": r.published,
                                    "last_modified": r.lastModified
                                    })
        except Exception as e:
            print(f"\nError during fetch for {cve}..\n -> {e} \n Retrying.\n")
            time.sleep(1)

def get_technique_list(file):
    with open(file, 'r') as f:
        reader = csv.DictReader(f, delimiter=';')
        return list(set([row['Technique'] for row in reader]))