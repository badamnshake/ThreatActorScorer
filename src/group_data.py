import pandas as pd
from mitreattack.stix20 import MitreAttackData
from pathlib import Path

base_path = Path(__file__).resolve().parent.parent

# Initialize variables to cache the loaded data
cached_data = None
incidents_data = None

def load_data():
    """
    Loads both group techniques data and incidents data if they haven't been loaded already.
    """
    global cached_data, incidents_data

    if incidents_data is None:
        incidents_data = load_group_incidents()  # Cache the processed incidents data for future calls
        print("Incidents data loaded successfully.")
        
    if cached_data is None:
        cached_data = load_group_data()  # Cache the processed group data for future calls
        print("Group data loaded successfully.")
    

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
    load_data()  # Ensure data is loaded

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
    load_data()  # Ensure data is loaded
    return list(cached_data.keys())


def get_group_incidents(group_id):
    """
    Retrieves incidents associated with a given group ID.
    """
    global incidents_data
    load_data()  # Ensure data is loaded
    return incidents_data.loc[incidents_data['actor'] == group_id]

def get_ttp_complexity_data():
    complexity_df = pd.read_csv(base_path / 'data/Techniques_with_Complexity_Scores_New.csv')
    return complexity_df  