# veris_data.py
import pandas as pd
from pathlib import Path 

base_path = Path(__file__).resolve().parent.parent

# Initialize a variable to cache the loaded data
cached_data = None

def load_veris_data():
    """Load the VERIS data from CSV files."""
    veris_df = pd.read_csv(base_path / 'data/veris_attack_mapping.csv')
    veris_impact_df = pd.read_csv(base_path / 'score/veris_impact.csv')

    # Clean the veris_df
    veris_df = veris_df.drop(veris_df[veris_df['mapping_type'] == 'non_mappable'].index)
    veris_df = veris_df.drop(columns=['attack_version', 'technology_domain', 'mapping_type',
                                       'references', 'comments', 'organization', 'creation_date',
                                       'last_update', 'mapping_framework_version', 'mapping_framework', 'Unnamed: 0'])
    
    # Clean the veris_impact_df
    veris_impact_df = veris_impact_df.drop(columns=['description', 'id'])

    # Create DataFrame with "action"
    veris_df_action = veris_df[veris_df['capability_group'].str.contains('action')]
    veris_df_action.loc[:, 'capability_group'] = veris_df_action['capability_group'].str.replace('action.', '', regex=False)
    veris_df_action.loc[:, 'capability_group'] = veris_df_action['capability_group'].str.replace('attribute.', '', regex=False)
    veris_df_action.loc[:, 'capability_id'] = veris_df_action['capability_id'].str.replace(r'action\.\w+\.(variety|vector)\.', '', regex=True)
    veris_df_action = pd.merge(veris_df_action, veris_impact_df, left_on='capability_id', right_on='attack_type', how='left')
    veris_df_action.drop(columns=['capability_id'], inplace=True)

    # Create DataFrame with "attribute"
    veris_df_attribute = veris_df[veris_df['capability_group'].str.contains('attribute')]
    veris_df_attribute.loc[:, 'capability_group'] = veris_df_attribute['capability_group'].str.replace('attribute.', '', regex=False)

    return veris_df_action, veris_df_attribute

def extract_veris_data(ttps):
    """Extract and process VERIS data based on provided TTPs."""
    global cached_data
    if cached_data is None:
        cached_data = load_veris_data()

    veris_df_action, veris_df_attribute = cached_data

    # Filter veris data based on supplied TTPs
    veris_df = veris_df_action.loc[veris_df_action['attack_object_id'].isin(ttps)].reset_index(drop=True)
    veris_df_attribute = veris_df_attribute.loc[veris_df_attribute['attack_object_id'].isin(ttps)].reset_index(drop=True)

    # Group by attack_object_id and calculate the average severity
    average_severity = veris_df.groupby('attack_object_id')['severity'].mean().reset_index()

    # Define severity categories
    bins = [0, 4, 6, 8, 10]
    labels = ['Low', 'Moderate', 'High', 'Critical']

    # Rename columns for clarity
    average_severity.columns = ['ttp', 'severity']

    # Create a new column for severity levels
    average_severity['severity_level'] = pd.cut(average_severity['severity'], bins=bins, labels=labels, right=True)

    # Count occurrences of each severity level
    severity_counts = average_severity['severity_level'].value_counts().reset_index();
    severity_counts.columns = ['severity_level', 'count']

    # order based on Low Moderate High critical
    severity_order = pd.CategoricalDtype(['Low', 'Moderate', 'High', 'Critical'], ordered=True)
    severity_counts['severity_level'] = severity_counts['severity_level'].astype(severity_order)

    severity_counts = severity_counts.sort_values('severity_level', ignore_index=True)

    # Return the processed data
    return average_severity, severity_counts, veris_df_attribute.groupby('capability_group')['capability_id'].count().reset_index()
