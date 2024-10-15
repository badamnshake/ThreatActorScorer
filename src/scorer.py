from group_data import get_group_incidents
from veris_data import extract_veris_data
from cvwe_data import extract_cvss_scores
from nist_data import extract_nist_data

# Manually defined values for Targeted Sector and Actor Type scoring
SECTOR_SCORES = {
    'Professional, Scientific, and Technical Services': 0.6,
    'Information': 0.9,
    'Educational Services': 0.5,
    'Arts, Entertainment, and Recreation': 0.3,
    'Finance and Insurance': 0.9,
    'Public Administration': 1.0,
    'Health Care and Social Assistance': 0.9,
    'Other Services (except Public Administration)': 0.4,
    'Retail Trade': 0.6,
    'Manufacturing': 0.8,
    'Administrative and Support and Waste Management and Remediation Services': 0.7,
    'Accommodation and Food Services ': 0.5,
    'Transportation and Warehousing': 0.8,
    'Utilities': 1.0,
    'Wholesale Trade': 0.7,
    'Agriculture, Forestry, Fishing and Hunting': 0.8,
    'Management of Companies and Enterprises': 0.6,
    'Real Estate and Rental and Leasing': 0.2,
    'Mining, Quarrying, and Oil and Gas Extraction': 0.8,
    'Construction': 0.4,
}

ACTOR_TYPE_SCORES = {
    'Nation-State': 1.0,
    'Criminals': 0.8,
    'Hacktivists': 0.4,
    'Hobbyists': 0.2,
    'Terrorists': 0.6,
}

# Calculate Complexity Score (C_i)
def calculate_complexity_score(capability_data):
    if capability_data.empty:
        return 0
    complexity_sum = capability_data['complexity_score'].sum()  # Assuming complexity_score is pre-calculated
    num_ttps = len(capability_data)
    return complexity_sum / num_ttps if num_ttps else 0

# Calculate Frequency Score (F_i)
def calculate_frequency_score(incident_data, total_incidents):
    num_actor_incidents = len(incident_data)
    return num_actor_incidents / total_incidents if total_incidents else 0

# Calculate Impact Score (I_i)
def calculate_impact_score(veris_data, cvss_data, cvss_weight=0.5):
    sophistication = veris_data['impact_score'].mean()  # Assuming impact_score is pre-calculated
    avg_cvss = cvss_data['cvss'].mean()
    return (sophistication + (avg_cvss * cvss_weight)) / (1 + cvss_weight)

# Calculate Mitigation Score (M_i)
def calculate_mitigation_score(nist_data, num_ttps, w_t=0.7, w_c=0.3):
    technique_mitigations = len(nist_data[nist_data['mitigation_type'] == 'technique'])
    cve_mitigations = len(nist_data[nist_data['mitigation_type'] == 'cve'])
    return (w_t * technique_mitigations + w_c * cve_mitigations) / (num_ttps * (w_t + w_c)) if num_ttps else 0

# Calculate Sector Score (S_i)
def calculate_sector_score(sector):
    return SECTOR_SCORES.get(sector, 0.5)  # Default to 0.5 if sector is not in the list

# Calculate Actor Type Score (A_i)
def calculate_actor_type_score(actor_type):
    return ACTOR_TYPE_SCORES.get(actor_type, 0.5)  # Default to 0.5 if actor type is not in the list

# Main scoring function
def score_threat_actor(group_id, actor_sector, actor_type, total_incidents):
    try:
        # Fetch data for the group
        capability_data = extract_veris_data(group_id)
        nist_data = extract_nist_data(group_id)
        cvss_data = extract_cvss_scores(group_id)
        incident_data = get_group_incidents(group_id)

        # Calculate the scores
        complexity_score = calculate_complexity_score(capability_data)
        frequency_score = calculate_frequency_score(incident_data, total_incidents)
        impact_score = calculate_impact_score(capability_data, cvss_data)
        mitigation_score = calculate_mitigation_score(nist_data, len(capability_data))
        sector_score = calculate_sector_score(actor_sector)
        actor_type_score = calculate_actor_type_score(actor_type)

        # Combine the scores using weights (or equal weights if no specific weight is given)
        total_score = (
            complexity_score * 0.2 +
            frequency_score * 0.2 +
            impact_score * 0.3 +
            mitigation_score * 0.1 +
            sector_score * 0.1 +
            actor_type_score * 0.1
        )
        return total_score

    except Exception as e:
        print(f"Error scoring threat actor: {e}")
        return 0

