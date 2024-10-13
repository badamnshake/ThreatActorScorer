import pandas as pd
from mitreattack.stix20 import MitreAttackData
from pathlib import Path

base_path = Path(__file__).resolve().parent.parent

# Initialize a variable to cache the loaded data
cached_data = None
incidents_data = None

def load_data():
    global cached_data
    global incidents_data

    if incidents_data is None:
        incidents_data = load_group_incidents()  # Cache the processed data for future calls
    if cached_data is None:
        cached_data = load_group_data()  # Cache the processed data for future calls
    

def get_group_name(group_id, df):
    result = df.loc[df['id'] == group_id, 'name']
    return result.iloc[0] if not result.empty else None

def load_group_data():
    mitre_attack_data = MitreAttackData(str(base_path / 'data/enterprise-attack.json'))

    group_mapping = pd.read_csv(base_path / 'data/threat_actor_groups_aliases.csv')

    # Get the data of techniques used by all the groups
    technique_using_groups = mitre_attack_data.get_all_techniques_used_by_all_groups()

    # Extracting techniques used by a group
    groups_list = {}

    for id, technique in technique_using_groups.items():
        group_id = get_group_name( mitre_attack_data.get_attack_id(id), group_mapping)
        if(group_id == None): continue
        ttp_list = []

        # Get TTP ids of techniques
        for t in technique:
            external_id = t['object'].external_references[0].external_id 
            ttp_list.append(external_id)

        groups_list[group_id] = ttp_list

    return groups_list  # Return the populated groups_list

def load_group_incidents():
    df = pd.read_csv(base_path / 'data/ta_incidents.csv')
    df['event_date'] = pd.to_datetime(df['event_date'])
    df.sort_values('event_date')
    return df
    

def get_ttps_of_group(group_id):
    global cached_data
    if group_id in cached_data:
        return cached_data[group_id]
    else:
        return f"Group ID {group_id} not found"

def get_all_groups():
    global cached_data
    return list(cached_data.keys())


def get_group_incidents(group_id):
    global incidents_data
    return incidents_data.loc[incidents_data['actor'] == group_id]
    