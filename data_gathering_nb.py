from OCloud_Data_Gathering import *
from stix2 import FileSystemSource

pull_clone_gitrepo('./data', 'https://github.com/mitre/cti')
fs = FileSystemSource('./data/capec/2.1', encoding='utf-8')

techniques_df = generate_techniques_dataframe()
# print the whole dataframe to a file
grouped = get_grouped_o_cloud_technique(file='./mapping/o_cloud_technique_mapping_without_subtechniques.csv', drop_duplicates=True)
techniques_capecs = get_technique_capecs_id(grouped,techniques_df)
#write_ids_to_file(techniques_capecs, file ='./mapping/o_cloud_capecs_per_technique.csv')
#t_cwe_cve_dict = find_cwe_for_capec(techniques_capecs,fs)
#write_dict_to_file(t_cwe_cve_dict, "./scans/t-cwe-cve-dict.json")
#print("-------------------------------------------")
# get data from column "Technique" from file "o_cloud_technique_mapping_without_subtechniques.csv"
file = './mapping/o_cloud_technique_mapping_without_subtechniques.csv'

technique_list = get_technique_list(file)
print("Technique List: ", technique_list)
print("Technique List Length: ", len(technique_list))
# Start timetracking
start = time.time()
techniques_capecs_custom = get_technique_capecs_id_custom(technique_list, "./data")
# join with CAPECs found using original ACEMA methode and remove duplicates
techniques_capecs_custom = [(t[0], list(set(t[1] + techniques_capecs[technique_list.index(t[0])][1]))) for t in techniques_capecs_custom]
write_ids_to_file(techniques_capecs_custom, file ='./mapping/o_cloud_capecs_per_technique.csv')
# time tracking ends when all CVE Data is gathered inside this function
t_cwe_cve_dict_custom = find_cwe_for_capec(start, techniques_capecs_custom,fs)
write_dict_to_file(t_cwe_cve_dict_custom, "./scans/t-cwe-cve-dict.json")

#print("Data Gathering using ACEMA impl")
#print_capec_stats(techniques_capecs)
#print_cwe_stats(t_cwe_cve_dict)
print ("Data Gathering using custom impl")
print_capec_stats(techniques_capecs_custom)
print_cwe_stats(t_cwe_cve_dict_custom)