import pandas as pd
import re
from pathlib import Path 

base_path = Path(__file__).resolve().parent.parent

# Initialize a variable to cache the loaded data
cached_data = None

def load_data():
    """Load the CVSS data and cache it for reuse."""
    
    global cached_data
    if cached_data is None:
        cached_data = load_cvss_data()  # Cache the processed data for future calls



def load_cvss_data():

    # Load the CSV and Excel files
    cve_df = pd.read_csv(base_path / 'data/cve_mapping.csv')
    cwe_df = pd.read_excel( base_path / 'data/cve_to_cwe.xlsx')

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

    # Display the result
    return result



def extract_cvss_data(ttps):
    global cached_data
    cvedf = cached_data.loc[cached_data['ttp'].isin(ttps)].reset_index(drop=True)
    cvedf.drop(columns=['mapping_type_count'], inplace=True)
    return cvedf, get_ttps_by_year(cvedf.copy())




def extract_cve_year(cve):
    match = re.search(r'CVE-(\d{4})', cve)
    return int(match.group(1)) if match else None


def get_ttps_by_year(df):

    df['cve_years'] = [[extract_cve_year(cve) for cve in cves.split(', ') if cve] for cves in df['cves']]

    # Combine logic for finding most recent year
    df['most_recent_cve_year'] = df['cve_years'].apply(lambda years: max([y for y in years if y is not None]) if years else None)

    # Group by TTP and count
    ttp_year_summary = df.groupby('most_recent_cve_year').size().reset_index(name='ttp_count').sort_values(by='most_recent_cve_year', ascending=False)

    return ttp_year_summary
    