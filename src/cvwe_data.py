import pandas as pd
import re
from pathlib import Path 

base_path = Path(__file__).resolve().parent.parent

# Initialize variables to cache the loaded data
cached_data = None
cve_with_scores = None  # Ensure this variable is declared globally
cwe_mitigations = None

def load_data():
    """Load the CVSS data and cache it for reuse."""
    global cached_data
    global cve_with_scores
    global cwe_mitigations

    if cached_data is None:
        cached_data, cve_with_scores = load_cvss_data()
    cwe_mitigations = load_cwe_mitigations()

def load_cvss_data():
    """Load and process CVSS data from CSV and Excel files."""
    # Load the CSV and Excel files
    cve_df = pd.read_csv(base_path / 'data/cve_mapping.csv')
    cwe_df = pd.read_excel(base_path / 'data/cve_to_cwe.xlsx')

    # Clean up and drop unnecessary columns in cve_df
    cve_df = cve_df.drop(columns=[
        'attack_version', 'technology_domain', 'references', 'comments', 
        'organization', 'creation_date', 'last_update', 
        'mapping_framework_version', 'mapping_framework', 'Unnamed: 0'])

    # Rename columns in cwe_df and drop description
    cwe_df.rename(columns={
        "CVE-ID": "capability_id", "CVSS-V3": "cvss_v3", "CVSS-V2": "cvss_v2", 
        "SEVERITY": "severity", "CWE-ID": "cwe_id", "ID": "id"
    }, inplace=True)
    cwe_df = cwe_df.drop(columns=['DESCRIPTION'])
    cwe_df['severity'] = cwe_df['severity'].str.lower()

    # Merge cve_df with cwe_df on 'capability_id'
    cve_df = pd.merge(cve_df, cwe_df, how='left', on='capability_id')

    # Extract the year from the 'capability_group' and rename columns
    cve_df['capability_group'] = cve_df['capability_group'].str.extract(r'(\d{4})')
    cve_df.rename(columns={'capability_group': 'year', 'capability_id': 'cve'}, inplace=True)

    # Use CVSS v3 if available, otherwise fallback to CVSS v2
    cve_df['cvss'] = cve_df['cvss_v3'].combine_first(cve_df['cvss_v2'])

    # Drop unneeded columns
    cve_df.drop(columns=['id', 'cvss_v3', 'cvss_v2'], inplace=True)

    # Sort by 'year' to get the latest entries first
    df_sorted = cve_df.sort_values('year', ascending=False)

    # Strip any leading/trailing spaces in column names
    df_sorted.columns = df_sorted.columns.str.strip()

    # Grouping and processing the data
    result = df_sorted.groupby('attack_object_id').agg({
        'cve': lambda x: ', '.join(x),                        # Join CVEs by comma
        'cvss': ['max', 'mean'],                              # Get highest and average CVSS
        'cwe_id': lambda x: ', '.join(x),                     # Join CWE IDs by comma
        'mapping_type': lambda x: x.value_counts().to_dict()   # Count mapping types
    }).reset_index()

    # Flatten multi-level column names
    result.columns = ['ttp', 'cves', 'high_cvss', 'avg_cvss', 'cwes', 'mapping_type_count']
    
    #csv_file_path = base_path / 'data/ttp_cves_cwes.csv'
    #result[['ttp', 'cves', 'cwes']].to_csv(csv_file_path, index=False  

    return result, df_sorted

def extract_cvss_scores(ttps):
    """Extract CVSS scores for the given TTPs."""
    global cve_with_scores
    if cve_with_scores is None:
        load_data()  # Ensure the data is loaded if it's not already

    return cve_with_scores.loc[cve_with_scores['attack_object_id'].isin(ttps)]


def load_cwe_mitigations():
    """Load and process TTP-CVE-CWE and CWE mitigations data from CSV files."""
    # Load the TTP-CVE-CWE and CWE mitigations data
    # ttp_cves_cwes_path = base_path / 'data/ttp_cves_cwes.csv'
    # cwe_mitigations_path = base_path / 'data/cwe_mitigations.csv'

    # # Read the CSV files
    # ttp_cves_cwes_df = pd.read_csv(ttp_cves_cwes_path)
    # cwe_mitigations_df = pd.read_csv(cwe_mitigations_path)

    # # Clean and ensure columns are stripped of extra spaces
    # ttp_cves_cwes_df.columns = ttp_cves_cwes_df.columns.str.strip()
    # cwe_mitigations_df.columns = cwe_mitigations_df.columns.str.strip()

    # # Split and clean the 'CWE-ID' column in the ttp_cves_cwes_df
    # ttp_cves_cwes_df['CWE-ID'] = ttp_cves_cwes_df['CWE-ID'].str.split(',')
    # ttp_cves_cwes_df['CWE-ID'] = ttp_cves_cwes_df['CWE-ID'].apply(lambda x: [cwe.strip() for cwe in x])

    # # Ensure that the CWE-ID in cwe_mitigations_df is treated as a string for comparison
    # cwe_mitigations_df['CWE-ID'] = cwe_mitigations_df['CWE-ID'].astype(str)

    # # Initialize a list to store the final result with mitigation info
    # mitigation_results = []

    # # Loop through each TTP and check for CWE mitigations
    # for index, row in ttp_cves_cwes_df.iterrows():
    #     ttp = row['ttp']  # Get the TTP
    #     cwes = row['CWE-ID']  # Get the associated CWE-IDs

    #     mitigated_cwes = []
    #     unmitigated_cwes = []

    #     # Check each CWE-ID in the list
    #     for cwe in cwes:
    #         cwe = str(cwe).strip()  # Clean the CWE string
    #         cwe_data = cwe_mitigations_df[cwe_mitigations_df['CWE-ID'] == cwe]  # Filter for this CWE in cwe_mitigations

    #         if not cwe_data.empty:
    #             potential_mitigation = cwe_data['Potential_Mitigations'].values[0]
    #             if pd.notna(potential_mitigation) and potential_mitigation.strip():
    #                 mitigated_cwes.append(cwe)  # This CWE has a mitigation
    #             else:
    #                 unmitigated_cwes.append(cwe)  # No mitigation data
    #         else:
    #             unmitigated_cwes.append(cwe)  # CWE not found

    #     # Calculate the ratio of mitigated CWEs
    #     total_cwes = len(cwes)
    #     mitigated_count = len(mitigated_cwes)
    #     mitigation_ratio = mitigated_count / total_cwes if total_cwes > 0 else 0

    #     # Store the results
    #     mitigation_results.append({
    #         'ttp': ttp,
    #         'total_cwes': total_cwes,
    #         'mitigated_cwes': mitigated_cwes,
    #         'unmitigated_cwes': unmitigated_cwes,
    #         'mitigation_ratio': mitigation_ratio
    #     })
    #     m = pd.DataFrame(mitigation_results)
    #     m.to_csv("mitigation_results.csv")
    
    return pd.read_csv(base_path / 'data/mitigation_results.csv')


def extract_cwe_mitigations(ttps):
    """Extract the mitigation_ratio column for specific TTPs and store in a global variable."""
    global cwe_mitigations
    mitigations_df = cwe_mitigations # Load the CWE mitigation data

    # Filter only the rows where TTP is in the provided ttps list
    filtered_mitigations = mitigations_df[mitigations_df['ttp'].isin(ttps)]

    # If no mitigations are found for the TTPs, set the ratio to 0
    if filtered_mitigations.empty:
        return 0.0

    # Sum up the mitigation ratios for each TTP
    mitigation_ratio_sum = filtered_mitigations['mitigation_ratio'].sum()

    # Calculate the average mitigation ratio if applicable
    total_ttps = len(ttps)
    if total_ttps > 0:
        mitigation_ratio_avg = mitigation_ratio_sum / total_ttps
    else:
        mitigation_ratio_avg = 0.0  # Set to 0 if no TTPs

    return mitigation_ratio_avg  # Return the average mitigation ratio