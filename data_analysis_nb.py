from OCloud_Data_Analysis import *

techniques_df = generate_techniques_dataframe()

grouped = get_grouped_o_cloud_data('./mapping/o_cloud_technique_mapping_without_subtechniques.csv')

grouped = get_grouped_o_cloud_data('./mapping/o_cloud_technique_mapping_without_subtechniques.csv')
threats_tactics = get_threats_tactics(grouped, techniques_df)
write_threats_tactics('./mapping/automatic_o_cloud_count_tactics_per_threat.csv', threats_tactics)
grouped_by_tactic = get_grouped_o_cloud_data('./mapping/o_cloud_technique_mapping_without_subtechniques.csv', group_by='Tactic')
grouped_by_tactic.describe()
ax = generate_ax('./mapping/automatic_o_cloud_count_tactics_per_threat.csv')
plot_and_save_heat(ax, './img/tactics_heatmap.pdf')

fetched_info = get_json_data('./scans/t-cwe-cve-dict.json')
# Write smaller file for use in the dashboard
#generate_json_with_scores(fetched_info)

sum_overall_technique_df,mean_overall_technique_df, mean_overall_technique_not_grouped_df = gen_statistics_per_tactic(fetched_info)
plot_and_save_bar(counts = mean_overall_technique_not_grouped_df,file="./img/mean_cvss_scores_per_technique.pdf",c_palette="tab10",x_axis="Technique",y_axis="Score",rotate_bar_description=0,set_size=True, bar_edge_color="White")
plot_and_save_bar(counts = sum_overall_technique_df,file="./img/sum_of_cvss_scores_per_technique.pdf",c_palette="tab10",x_axis="Technique",y_axis="Score",phue="Severity",rotate_bar_description=0,set_size=True, bar_edge_color="White")
plot_and_save_bar(counts = mean_overall_technique_df,file="./img/mean_cvss_scores_per_technique_and_sev.pdf",c_palette="tab10",x_axis="Technique",y_axis="Score",phue="Severity",rotate_bar_description=0,set_size=True, bar_edge_color="White")

mapping = {"AC": "Access Complexity", "Au": "Authentication",
                   "AV": "AccessVector", "C": "Confidentiality Impact",
                   "I": "Integrity Impact", "A": "Availability Impact"}
vector_df_network = gen_vector_df(fetched_info,"access_vector", "NETWORK")
vector_df_local = gen_vector_df(fetched_info,"access_vector", "LOCAL")
vector_df_high = gen_vector_df(fetched_info,"v2_score", "HIGH")
vector_df_low = gen_vector_df(fetched_info,"v2_score", "LOW")
vector_df_medium = gen_vector_df(fetched_info,"v2_score", "MEDIUM")
print("high vector count: ",len(vector_df_high)/6)
print("medium vector count: ",len(vector_df_medium)/6)
print("low vector count: ",len(vector_df_low)/6)

vector_df_high = insert_length_wise(vector_df_high)
vector_high_avgs = vector_df_high.mean(axis=0)
vector_df_low = insert_length_wise(vector_df_low)
vector_low_avgs = vector_df_low.mean(axis=0)
vector_df_medium = insert_length_wise(vector_df_medium)
vector_medium_avgs = vector_df_medium.mean(axis=0)
vector_df_network = insert_length_wise(vector_df_network)
vector_network_avgs = vector_df_network.mean(axis=0)
vector_df_local = insert_length_wise(vector_df_local)
vector_local_avgs = vector_df_local.mean(axis=0)
    
vectors = []
visited_cves = []
for technique in fetched_info:
    for cwes in technique["t_findings"]:
        for cves in cwes["c_findings"]:
            for cve in cves["cves"]:
                if cve["cve_id"] in visited_cves:
                    continue
                visited_cves.append(cve["cve_id"])
                score = get_scores_from_vector(cve["v2_vector"])
                vectors.append(score)
print("vectors of unique cves: ",len(vectors))
vector_df = pd.DataFrame(vectors, columns=['AV','AC', 'Au', 'C', 'I', 'A'])
vector_avgs = vector_df.mean(axis=0)
print(vector_avgs)
df = pd.DataFrame({
'group': ['Overall'],
'Access \nVector': [vector_avgs.AV],
'Access \nComplexity': [vector_avgs.AC],
'Authentication': [vector_avgs.Au],
'Confidentiality \nImpact': [vector_avgs.C],
'Integrity \nImpact': [vector_avgs.I],
'Availability \nImpact': [vector_avgs.A]
})
plot_and_save_radar(df,filled=True,dotted=True, file="./img/radar_plot_vector_overall.pdf")

df = pd.DataFrame({
    'group': ['High', 'Medium', 'Low'],
    'Access \nVector': [vector_high_avgs.AV, vector_medium_avgs.AV, vector_low_avgs.AV],
    'Access \nComplexity': [vector_high_avgs.AC, vector_medium_avgs.AC, vector_low_avgs.AC],
    'Authentication': [vector_high_avgs.Au, vector_medium_avgs.Au, vector_low_avgs.Au],
    'Confidentiality \nImpact': [vector_high_avgs.C, vector_medium_avgs.C, vector_low_avgs.C],
    'Integrity \nImpact': [vector_high_avgs.I, vector_medium_avgs.I, vector_low_avgs.I],
    'Availability \nImpact': [vector_high_avgs.A, vector_medium_avgs.A, vector_low_avgs.A]
})
plot_and_save_radar(df, file="./img/radar_plot_vector_per_severity.pdf")

df = pd.DataFrame({
'group': ['Overall', 'Network', 'Local'],
'Access \nVector': [vector_avgs.AV, vector_network_avgs.AV, vector_local_avgs.AV],
'Access \nComplexity': [vector_avgs.AC, vector_network_avgs.AC, vector_local_avgs.AC],
'Authentication': [vector_avgs.Au, vector_network_avgs.Au, vector_local_avgs.Au],
'Confidentiality \nImpact': [vector_avgs.C, vector_network_avgs.C, vector_local_avgs.C],
'Integrity \nImpact': [vector_avgs.I, vector_network_avgs.I, vector_local_avgs.I],
'Availability \nImpact': [vector_avgs.A, vector_network_avgs.A, vector_local_avgs.A]
})  
plot_and_save_radar(df, file="./img/radar_plot_vector_per_access.pdf")

df = pd.DataFrame({
'group': ['Overall'],
'Confidentiality \nImpact': [vector_avgs.C],
'Integrity \nImpact': [vector_avgs.I],
'Availability \nImpact': [vector_avgs.A]
})  
plot_and_save_radar(df, file="./img/radar_base_impact.pdf", only_npc=True)

o_cloud = pd.read_csv('./mapping/o_cloud_technique_mapping_without_subtechniques.csv', sep=';', index_col=0)
grouped = get_grouped_o_cloud_data('./mapping/o_cloud_technique_mapping_without_subtechniques.csv',drop_duplicates=False)
o_ran_threats_severity_acc,o_ran_threats_severity_mean  = gen_o_ran_threats_severity(grouped,sum_overall_technique_df)
plot_and_save_bar_broken_axis(o_ran_threats_severity_acc, file = './img/sum_of_cvss_scores_per_threat.pdf')
plot_and_save_bar_broken_axis(o_ran_threats_severity_mean, file = './img/mean_cvss_scores_per_threat.pdf')

print_stats(fetched_info)