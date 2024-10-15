# Manually defined values for Targeted Sector and Actor Type scoring
SECTOR_SCORES = {
    'Professional, Scientific, and Technical Services': 0.6,
    'Information': 0.9,
    'Educational Services': 0.5,
    'Finance and Insurance': 0.9,
    'Public Administration': 1.0,
    'Health Care and Social Assistance': 0.9,
    'Retail Trade': 0.6,
    'Manufacturing': 0.8,
    'Utilities': 1.0,
    # Add remaining sectors...
}

ACTOR_TYPE_SCORES = {
    'Nation-State': 1.0,
    'Criminals': 0.8,
    'Hacktivists': 0.4,
    'Hobbyists': 0.2,
    'Terrorists': 0.6,
}


def get_score_for_threat_actor(veris_impact, cvss_data, frequency, sector, actor_type):
    # impact score
    avg_cvss = cvss_data['cvss'].mean()
    sophistication = veris_impact['severity'].mean()
    cvss_weight = 0.5
    impact_score =  (sophistication + (avg_cvss * cvss_weight)) / (1 + cvss_weight)

    # frequency score
    frequency_score = frequency

    # sector score
    sector_score = SECTOR_SCORES.get(sector, 0.5)

    # actor type score
    actor_type_score = ACTOR_TYPE_SCORES.get(actor_type, 0.5)  # Default to 0.5 if actor type is not in the list

    # mitigation score
    cwe_mit = cvss_data['cwe_id'].nunique() / len(cvss_data)
    technique_mit = 0
    mitigation_score =  7 * technique_mit + 3 * cwe_mit

    complexity_score = veris_impact['severity'].mean()

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

    

# def get_score_for_threat_actor_manual():
    # return