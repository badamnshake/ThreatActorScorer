from mitreattack.stix20 import MitreAttackData
from pathlib import Path

base_path = Path(__file__).resolve().parent.parent

# Initialize a variable to cache the loaded data
cached_data = None

def load_data():
    """Load the VERIS data and cache it for reuse."""
    
    global cached_data
    if cached_data is None:
        cached_data = load_group_data()  # Cache the processed data for future calls

def load_group_data():
    # Load the group data
    mitre_attack_data = MitreAttackData(str(base_path / 'data/enterprise-attack.json'))
    # Get the data of techniques used by all the groups
    technique_using_groups = mitre_attack_data.get_all_techniques_used_by_all_groups()

    # Extracting techniques used by a group
    groups_list = {}

    for id, technique in technique_using_groups.items():
        group_id = mitre_attack_data.get_attack_id(id)
        ttp_list = []

        # Get TTP ids of techniques
        for t in technique:
            external_id = t['object'].external_references[0].external_id 
            ttp_list.append(external_id)

        groups_list[group_id] = ttp_list

    return groups_list  # Return the populated groups_list

def get_ttps_of_group(group_id):
    global cached_data
    if cached_data is None:
        cached_data = load_group_data()
    
    # Check if the group_id exists in cached_data
    if group_id in cached_data:
        return cached_data[group_id]
    else:
        return f"Group ID {group_id} not found"

def get_all_groups():
    global cached_data
    if cached_data is None:
        cached_data = load_group_data()

    return list(cached_data.keys())
