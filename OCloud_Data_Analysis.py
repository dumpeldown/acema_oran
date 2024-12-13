import csv
import itertools
import json
import statistics
from collections import Counter

import matplotlib.pyplot as plt
import mitreattack.attackToExcel.attackToExcel as attackToExcel
import mitreattack.attackToExcel.stixToDf as stixToDf
import numpy as np
import pandas as pd
import seaborn as sns
from numpy import pi
from pandas.api.types import CategoricalDtype

PLOT_DPI = 300


def get_scores_from_vector(v):
    base_scores = {"AC": {"H": 0.35, "M": 0.61, "L": 0.71}, "Au": {"M": 0.45, "S": 0.56, "N": 0.704, },
                   "AV": {"L": 0.395, "A": 0.646, "N": 1}, "C": {"N": 0, "P": 0.275, "C": 0.660},
                   "I": {"N": 0, "P": 0.275, "C": 0.660}, "A": {"N": 0, "P": 0.275, "C": 0.660}}

    vector_list = []

    for metric in v.split("/"):
        m = metric.split(":")
        vector_list.append(base_scores[m[0]][m[1]])
    return vector_list


def generate_techniques_dataframe():
    # download and parse ATT&CK STIX data
    attackdata = attackToExcel.get_stix_data("enterprise-attack")
    # get Pandas DataFrames for techniques, associated relationships, and citations
    techniques_data = stixToDf.techniquesToDf(attackdata, "enterprise-attack")
    return techniques_data["techniques"]


def generate_ax(file):
    data = pd.read_csv(file)
    fp = data.pivot_table(index='Name', columns='Tactic', values='Count')

    return sns.heatmap(
        fp,
        vmin=1, vmax=15, center=7.5,
        cmap=sns.color_palette("Spectral_r", 5, as_cmap=True),
        square=False
    )


def get_grouped_o_cloud_data(file, drop_duplicates: bool = False, group_by: str = "Name"):
    o_cloud = pd.read_csv(file, sep=';', index_col=0)
    if drop_duplicates:
        o_cloud = o_cloud.drop_duplicates(subset=["Technique"])
    return o_cloud.groupby(group_by)


def gen_counted_accourences_per_platform(grouped, techniques_df):
    platforms = []
    for name, group in grouped:
        for i in group["Technique"].drop_duplicates():
            for platform in techniques_df[techniques_df["ID"].str.contains(i)]["platforms"]:
                platforms.append(platform.split(", "))
    return pd.Series(list(itertools.chain(*platforms))).value_counts().rename_axis('Platform').reset_index(
        name='Counted occurencies')


def save_plot(file):
    if file is not None:
        plt.savefig(file, dpi=PLOT_DPI, transparent=True, bbox_inches="tight", pad_inches=0.3)


def plot_and_save_bar(counts, file, show_title: bool = False, show_x_axis_descrition: bool = True, grid: bool = True,
                      half_width: bool = False, c_palette="mako",
                      rotate_bar_description: int = 45, bar_edge_color='black', x_axis="Platform",
                      y_axis="Counted occurencies", phue=None, set_size: bool = False):
    sns.set_style("whitegrid")
    if half_width:
        bwidth = 0.5
    else:
        bwidth = 0.8

    if set_size:
        plt.figure(figsize=(25, 6))
    sc_bar = sns.barplot(x=x_axis, y=y_axis, data=counts, palette=c_palette, edgecolor=bar_edge_color, width=bwidth,
                         hue=phue)
    if not grid:
        plt.grid(visible=False)
    if not show_x_axis_descrition:
        plt.xlabel('')
    if show_title:
        plt.title('Listed platforms for attack techniques')

    plt.xticks(rotation=rotate_bar_description)
    save_plot(file)


def get_threats_tactics(grouped, techniques_df):
    threats_tactics = []

    for name, group in grouped:
        tactics = []
        for i in group["Technique"].drop_duplicates():
            for tactic in techniques_df[techniques_df["ID"].str.contains(i)]["tactics"]:
                for t in tactic.split(", "):
                    tactics.append(t)
        threats_tactics.append((name, Counter(tactics)))

    return threats_tactics


def write_threats_tactics(file, threats_tactics):
    f = open(file, 'w')
    writer = csv.writer(f)
    writer.writerow(['Name', 'Count', 'Tactic'])

    for t_name, t_counter in threats_tactics:
        for tactic in t_counter:
            writer.writerow([t_name, t_counter[tactic], tactic])

    f.close()


def plot_and_save_heat(ax, file=None):
    ax.set_xticklabels(
        ax.get_xticklabels(),
        rotation=45,
        horizontalalignment='right'
    )

    plt.grid(visible=False)
    save_plot(file)


def get_json_data(file):
    data = json.load(open(file))
    return data["data"]


def generate_per_technique_df(fetched_info):
    overall_df = pd.DataFrame(columns=["avg_base", "avg_impact", "avg_exploitability", "technique"])
    for technique in fetched_info:
        for cwes in technique["t_findings"]:
            inter_df = pd.DataFrame(columns=["avg_base", "avg_impact", "avg_exploitability"])

            for cves in cwes["c_findings"]:
                if type(cves) is str:
                    continue
                if len(cves["cves"]) > 0:
                    df = pd.DataFrame.from_dict(cves["cves"])
                    avg_v2_score = statistics.mean(df['v2_score'].to_list())
                    avg_v2_impact_score = statistics.mean(df['v2_impact_score'].to_list())
                    avg_v2_exploitability_score = statistics.mean(df['v2_exploitability_score'].to_list())
                    new_df = pd.DataFrame([[avg_v2_score, avg_v2_impact_score, avg_v2_exploitability_score]],
                                          columns=["avg_base", "avg_impact", "avg_exploitability"])

                    if inter_df.empty:
                        inter_df = pd.DataFrame(new_df)
                    else:
                        inter_df = pd.concat([inter_df, new_df], ignore_index=True)

                inter_df["technique"] = technique["technique_id"]
            overall_df = pd.concat([overall_df, inter_df], ignore_index=True)

    return overall_df


def print_data_per_tecnique(grouped, overall_df):
    for name, group in grouped:
        avgs_per_technique = pd.DataFrame()

        for technique_id in group["Technique"]:
            avgs_per_technique = pd.concat([avgs_per_technique, overall_df.query("technique == @technique_id")])

        print(
            f"Impact: {avgs_per_technique['avg_impact'].mean()} | Exploitability: {avgs_per_technique['avg_exploitability'].mean()} | Base: {avgs_per_technique['avg_base'].mean()} | ")


def print_stats(fetched_info):
    avg_v2_score = {}
    avg_v2_impact_score = []
    avg_v2_exploitability_score = []

    count_capec = 0
    count_cwe = 0
    count_cve = 0
    count_teq = 0

    for technique in fetched_info:
        teq_name = technique["technique_id"]
        count_teq += 1
        for capec in technique["t_findings"]:
            count_capec += 1
            for cves in capec["c_findings"]:
                cves_df = pd.DataFrame.from_dict(cves["cves"])
                count_cwe += 1
                if cves_df.keys().size != 0:
                    count_cve += cves_df["v2_score"].keys().size
                    avg_v2_score[teq_name] = cves_df["v2_score"].mean()
                    avg_v2_impact_score.append(cves_df["v2_impact_score"].mean())
                    avg_v2_exploitability_score.append(cves_df["v2_exploitability_score"].mean())

    print(f"Count_teq: {count_teq}")
    print(f"Count_capec: {count_capec}")
    print(f"Count_cwe: {count_cwe}")
    print(f"Count_cve: {count_cve}")
    avg_v2_score = statistics.mean(avg_v2_score.values())
    print(f"avg_v2_score: {avg_v2_score}")
    avg_v2_impact_score = statistics.mean(avg_v2_impact_score)
    print(f"avg_v2_impact_score: {avg_v2_impact_score}")
    avg_v2_exploitability_score = statistics.mean(avg_v2_exploitability_score)
    print(f"avg_v2_exploitability_score: {avg_v2_exploitability_score}")


def gen_statistics_per_tactic(fetched_info):
    overall_df = pd.DataFrame(columns=["Score", "Severity", "Technique"])
    for technique in fetched_info:
        for cwes in technique["t_findings"]:
            inter_df = pd.DataFrame(columns=["Score", "Severity"])
            for cves in cwes["c_findings"]:
                if type(cves) is str:
                    continue
                if len(cves["cves"]) > 0:
                    df = pd.DataFrame.from_dict(cves["cves"])
                    new_df = pd.DataFrame(df['score'].to_list(), columns=["v", "Score", "Severity"]).drop(columns="v")
                    inter_df = pd.concat([inter_df, new_df], ignore_index=True)
                inter_df["Technique"] = technique["technique_id"]
            overall_df = pd.concat([overall_df, inter_df], ignore_index=True)

    # Create categorical datatype for the severity
    severity_order = CategoricalDtype(
        ['LOW', 'MEDIUM', 'HIGH'],
        ordered=True
    )
    # Cast data to category type with orderedness
    overall_df["Severity"] = overall_df["Severity"].astype(severity_order)
    return overall_df.groupby(["Technique", "Severity"])["Score"].sum().reset_index(), overall_df.groupby(["Technique", "Severity"])["Score"].mean().reset_index(), overall_df.groupby(["Technique"])["Score"].count().reset_index()

def generate_json_with_scores(fetched_info):
    new_json = []
    for technique in fetched_info:
        new_technique = {
            "technique_id": technique["technique_id"],
            "t_findings": [],
            "avg_score": 0
        }
        for cwes in technique["t_findings"]:
            new_cwes = {
                "capec_id": cwes["capec_id"],
                "c_findings": []
            }
            for cves in cwes["c_findings"]:
                if type(cves) is str:
                    continue
                new_cves = {
                    "cwe": cves["cwe"],
                    "cves": []
                }
                for cve in cves["cves"]:
                    new_cve = {
                        "id": cve["cve_id"],
                        "v2_score": cve["v2_score"],
                        "v2_impact_score": cve["v2_impact_score"],
                        "v2_exploitability_score": cve["v2_exploitability_score"]
                    }
                    new_cves["cves"].append(new_cve)
                new_cwes["c_findings"].append(new_cves)
            new_technique["t_findings"].append(new_cwes)
        # for each technique, calculate the average score of all its cves and add it to new_technique
        all_v2_scores = [cve["v2_score"] for cwes in new_technique["t_findings"] for cves in cwes["c_findings"] for cve in cves["cves"]]
        all_v2_impact_scores = [cve["v2_impact_score"] for cwes in new_technique["t_findings"] for cves in cwes["c_findings"] for cve in cves["cves"]]
        all_v2_exploitability_score = [cve["v2_exploitability_score"] for cwes in new_technique["t_findings"] for cves in cwes["c_findings"] for cve in cves["cves"]]
        if len(all_v2_scores) > 0:
            new_technique["avg_score"] = statistics.mean(all_v2_scores)
            new_technique["avg_impact_score"] = statistics.mean(all_v2_impact_scores)
            new_technique["avg_exploitability_score"] = statistics.mean(all_v2_exploitability_score)
        else:
            new_technique["avg_score"] = 0
            new_technique["avg_impact_score"] = 0
            new_technique["avg_exploitability_score"] = 0
        new_json.append(new_technique)
    with open('./scans/t-cwe-cve-dict_small.json', 'w') as f:
        json.dump({"data": new_json}, f)

def insert_length_wise(df, cols=('AV', 'AC', 'Au', 'C', 'I', 'A'), orogin_col='Vector'):
    # create list
    pd_list = df[orogin_col].to_list()

    # Define the shape of the DataFrame based on the desired dimensions
    num_rows = len(pd_list) // len(cols)  # Number of rows
    num_cols = len(cols)  # Number of columns

    # Reshape the list into the desired shape
    reshaped_array = np.array(pd_list).reshape(num_rows, num_cols)

    # Create the DataFrame
    return pd.DataFrame(reshaped_array, columns=cols)


def flatten_from_df(df, loc=0):
    values = df.loc[loc].drop('group').values.flatten().tolist()
    values += values[:1]
    return values


def set_pad_spwp(ax,):
    xticks = ax.xaxis.get_major_ticks()

    for tick in xticks:
        tick.set_pad(25)

    xticks[0].set_pad(30)
    xticks[1].set_pad(20)
    xticks[2].set_pad(20)
    xticks[3].set_pad(40)


def add_lables_background(categories, angles, ax, size1=9):
    plt.xticks(angles[:-1], categories, color='grey', size=size1)
    # Draw ylabels
    ax.set_rlabel_position(0)
    plt.yticks([0.25, 0.50, 0.75, 1], ["0.25", "0.50", "0.75", "1"], color="grey", size=7)
    plt.ylim(0, 1)

def add_npc_lables_background(categories, angles, ax, size1=9):
    plt.xticks(angles[:-1], categories, color='grey', size=size1)
    # Draw ylabels
    ax.set_rlabel_position(0)
    plt.yticks([0,0.1,0.2, 0.3], ["0", "0.1", "0.2", "0.3"], color="grey", size=7)
    plt.ylim(0, 1)


def init_spider_supplot():
    plt.figure(figsize=(10, 5))
    ax = plt.subplot(111, polar=True)
    return ax


def calc_axis_angles(df):
    categories = list(df)[1:]
    numcat = len(categories)
    angles = [n / float(numcat) * 2 * pi for n in range(numcat)]
    angles += angles[:1]
    return angles, categories


def plot_and_save_radar(df, file=None, groups=None, filled: bool = True, dotted: bool = False, only_npc=False):
    # What will be the angle of each axis in the plot? (we divide the plot / number of variable)
    angles, categories = calc_axis_angles(df)
    num_vars = len(categories)

    # If no groups are provided plot all groups in data Frame
    if groups is None:
        groups = df['group'].tolist()

    # Initialise the spider plot
    ax = init_spider_supplot()

    # If you want the first axis to be on top:
    ax.set_theta_offset(pi / 2)
    ax.set_theta_direction(-1)

    # Draw one axe per variable + add labels
    if only_npc:
        add_npc_lables_background(categories, angles, ax, num_vars)
    else:
        add_lables_background(categories, angles, ax, num_vars)

    # ------- PART 2: Add plots

    # Plot each individual = each line of the data
    for group in groups:
        index = df.loc[df['group'] == group].index.tolist()[0]
        values = flatten_from_df(df, index)
        print(group)
        colors = 'b'
        if group == 'High' or group == 'Overall':
            print("Setting color to red")
            colors = 'r'
        elif group == 'Medium' or group == 'Network':
            colors = 'y'
        elif group == 'Low' or group == 'Local': 
            colors = 'g'
        if dotted:
            ax.plot(angles, values, 'o-', linewidth=2, label=group)
        else:
            ax.plot(angles, values, color=colors,alpha=0.8, linewidth=2, linestyle='solid', label=group)
        if filled:
            ax.fill(angles, values, color=colors, alpha=0.1)

    # TODO: Looks better?
    #set_pad_spwp(ax)

    # Add legend
    plt.legend(loc='upper right', bbox_to_anchor=(0.1, 0.1))

    save_plot(file)


def plot_and_save_bar_broken_axis(o_ran_threats_severity, file):
    f, (ax_top, ax_bottom) = plt.subplots(ncols=1, nrows=2, sharex=True, gridspec_kw={'hspace': 0.05}, figsize=(25, 6))
    sns.set_style("whitegrid")
    sc_bar = sns.barplot(x="O-RAN Threat", y="Score", hue="Severity", data=o_ran_threats_severity, palette="crest",
                         edgecolor='black', ax=ax_top)
    sc_bar = sns.barplot(x="O-RAN Threat", y="Score", hue="Severity", data=o_ran_threats_severity, palette="crest",
                         edgecolor='black', ax=ax_bottom)

    sc_bar.grid(True)

    ax_top.set_ylim(bottom=110)  # those limits are fake
    ax_bottom.set_ylim(0, 100)

    sns.despine(ax=ax_bottom)
    sns.despine(ax=ax_top, bottom=True)

    ax = ax_top
    ax.legend()
    ax.get_xaxis().set_visible(False)
    ax2 = ax_bottom
    # remove one of the legend
    ax_bottom.legend_.remove()
    SMALL_SIZE = 10
    MEDIUM_SIZE = 13
    BIGGER_SIZE = 15

    plt.rc('font', size=SMALL_SIZE)  # controls default text sizes
    plt.rc('axes', titlesize=SMALL_SIZE)  # fontsize of the axes title
    plt.rc('axes', labelsize=BIGGER_SIZE)  # fontsize of the x and y labels
    plt.rc('xtick', labelsize=MEDIUM_SIZE)  # fontsize of the tick labels
    plt.rc('ytick', labelsize=11)  # fontsize of the tick labels
    plt.rc('legend', fontsize=MEDIUM_SIZE)  # legend fontsize
    plt.rc('figure', titlesize=BIGGER_SIZE)  # fontsize of the figure title
    save_plot(file)


def gen_o_ran_threats_severity(grouped, sum_overall_technique_df):
    o_ran_threats_severity_acc = pd.DataFrame()
    o_ran_threats_severity_mean = pd.DataFrame()
    

    for name, group in grouped:
        o_ran_threats = pd.DataFrame()
        for i in group["Technique"].drop_duplicates():
            o_ran_threats = pd.concat([o_ran_threats, sum_overall_technique_df.query("Technique == @i")])

        temp_o_ran_threat_severity_acc = o_ran_threats.groupby("Severity").sum(numeric_only=True).reset_index()
        temp_o_ran_threat_severity_mean = o_ran_threats.groupby("Severity").mean(numeric_only=True).reset_index()
        
        temp_o_ran_threat_severity_acc["O-RAN Threat"] = name
        temp_o_ran_threat_severity_mean["O-RAN Threat"] = name
        o_ran_threats_severity_acc = pd.concat([o_ran_threats_severity_acc, temp_o_ran_threat_severity_acc], ignore_index=True)
        o_ran_threats_severity_mean = pd.concat([o_ran_threats_severity_mean, temp_o_ran_threat_severity_mean], ignore_index=True)
        
    return o_ran_threats_severity_acc, o_ran_threats_severity_mean


def gen_vector_df(fetched_info, cve_attr, attr_value):
    vector_df = pd.DataFrame(columns=["Vector"])
    for technique in fetched_info:
        for cwes in technique["t_findings"]:
            for cves in cwes["c_findings"]:
                for cve in cves["cves"]:
                    if cve[cve_attr] == attr_value or cve_attr == "v2_score":
                        print(f"cve {cve['cve_id']} has {cve_attr} {attr_value}")
                        if attr_value == "HIGH" and cve["v2_score"] > 7 and cve["v2_score"] <= 10:
                            vector_df = pd.concat([vector_df, pd.DataFrame.from_records(
                                {"Vector": get_scores_from_vector(cve["v2_vector"])})], ignore_index=True)
                        elif attr_value == "MEDIUM" and cve["v2_score"] > 4 and cve["v2_score"] <= 7:
                            vector_df = pd.concat([vector_df, pd.DataFrame.from_records(
                                {"Vector": get_scores_from_vector(cve["v2_vector"])})], ignore_index=True)
                        elif attr_value == "LOW" and cve["v2_score"] >= 0 and cve["v2_score"] <= 4:
                            vector_df = pd.concat([vector_df, pd.DataFrame.from_records(
                                {"Vector": get_scores_from_vector(cve["v2_vector"])})], ignore_index=True)
                        elif cve_attr != "v2_score": # if attr_value is not HIGH, MEDIUM or LOW
                            vector_df = pd.concat([vector_df, pd.DataFrame.from_records(
                                {"Vector": get_scores_from_vector(cve["v2_vector"])})], ignore_index=True)
                    else:
                        continue
    return vector_df