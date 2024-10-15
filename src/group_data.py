import pandas as pd
from mitreattack.stix20 import MitreAttackData
from pathlib import Path

base_path = Path(__file__).resolve().parent.parent

# Initialize variables to cache the loaded data
cached_data = None
incidents_data = None
incident_counts = None
complexity_df = None
tech_wo_mit = None


def load_data():
    """
    Loads both group techniques data and incidents data if they haven't been loaded already.
    """
    global cached_data, incidents_data, incident_counts, complexity_df, tech_wo_mit



    complexity_df = pd.read_csv(base_path / 'data/techniques_with_complexity_scores.csv')
    tech_wo_mit = pd.read_csv(base_path / 'data/techniques_without_mitigations.csv', header=None, names=['Technique'])
    

    incidents_data = load_group_incidents()  # Cache the processed incidents data for future calls
    incident_counts = incidents_data.groupby('actor').size().reset_index(name='incident_count')
    # Step 2: Calculate min and max incident counts across all actors
    min_incidents = incident_counts['incident_count'].min()
    max_incidents = incident_counts['incident_count'].max()

    # Step 3: Apply the linear transformation to get the score for each actor
    incident_counts['score'] = 0.01+((incident_counts['incident_count'] - min_incidents) / (max_incidents - min_incidents))*(1-0.01)

        
    cached_data = load_group_data()  # Cache the processed group data for future calls
    

def get_group_name(group_id, df):
    """
    Retrieves the group name given the group ID from the group mapping DataFrame.
    """
    result = df.loc[df['id'] == group_id, 'name']
    return result.iloc[0] if not result.empty else None

def load_group_data():
    """
    Loads the techniques used by threat actor groups from MITRE ATT&CK and returns a mapping of group ID to TTP list.
    """
    try:
        mitre_attack_data = MitreAttackData(str(base_path / 'data/enterprise-attack.json'))
        group_mapping = pd.read_csv(base_path / 'data/threat_actor_groups_aliases.csv')

        # Get the data of techniques used by all the groups
        technique_using_groups = mitre_attack_data.get_all_techniques_used_by_all_groups()

        # Extracting techniques used by a group
        groups_list = {}
        for id, technique in technique_using_groups.items():
            group_id = get_group_name(mitre_attack_data.get_attack_id(id), group_mapping)
            if group_id is None:
                continue
            ttp_list = [t['object'].external_references[0].external_id for t in technique]
            groups_list[group_id] = ttp_list

        return groups_list  # Return the populated groups_list

    except Exception as e:
        print(f"Error loading group data: {e}")
        return {}

def load_group_incidents():
    """
    Loads and returns the incident data from a CSV file, sorted by event date.
    """
    try:
        df = pd.read_csv(base_path / 'data/ta_incidents.csv')
        df['event_date'] = pd.to_datetime(df['event_date'])
        df = df.sort_values('event_date')
        return df
    except Exception as e:
        print(f"Error loading incidents data: {e}")
        return pd.DataFrame()  # Return empty DataFrame on failure
    

def get_ttps_of_group(group_id):
    """
    Retrieves the list of TTPs for a given group ID.
    """
    global cached_data

    # Check if the group ID is in the cached data
    if group_id in cached_data:
        return cached_data[group_id]
    else:
        # Return an empty list instead of a string when the group is not found
        return []

def get_all_groups():
    """
    Returns a list of all group IDs.
    """
    global cached_data
    return list(cached_data.keys())


def get_group_incidents(group_id):
    """
    Retrieves incidents associated with a given group ID.
    """
    global incidents_data
    return incidents_data.loc[incidents_data['actor'] == group_id]

def get_frequency_score(actor_name):
    global incident_counts
    # return incident_counts.at[incident_counts.index[incident_counts['actor'] == actor_name][0], 'score']

    # Filter for matching actors
    matching_indices = incident_counts.index[incident_counts['actor'] == actor_name]

    # Check if there are any matching indices
    if len(matching_indices) > 0:
        return incident_counts.at[matching_indices[0], 'score']
    else:
        #print(f"No matching rows for actor: {actor_name}")
        return 0  # Handle the case where no matches are found


def get_ttp_complexity_data():
    global complexity_df
    return complexity_df  

def get_complexity_score(ttps):
    global complexity_df
    return complexity_df.loc[complexity_df["ID"].isin(ttps)]['complexity score'].mean()

def get_techniques_wo_mitigations(ttps):
    global tech_wo_mit
    matches = tech_wo_mit[tech_wo_mit["Technique"].isin(ttps)]
    return len(matches) / len(tech_wo_mit)
    