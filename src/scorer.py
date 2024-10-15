import numpy as np
import pandas as pd
# Manually defined values for Targeted Sector and Actor Type scoring
SECTOR_SCORES = {
    'Professional, Scientific, and Technical Services': 0.6,
    'Information': 0.9,
    'Educational Services': 0.5,
    'Arts, Entertainment, and Recreation':0.3,
    'Finance and Insurance': 0.9,
    'Public Administration': 1.0,
    'Health Care and Social Assistance': 0.9,
    'Other Services (Except Public Administration)': 0.4,
    'Retail Trade': 0.6,
    'Manufacturing': 0.8,
    'Administrative, Support, Waste Management & Remediation Services': 0.7,
    'Accomodation & Food Services': 0.5,
    'Transportation & Warehousing': 0.8,
    'Utilities': 1.0,
    'Wholesale Trade': 0.7,
    'Agriculture, Forestry, Fishing & Hunting': 0.8,
    'Management of Companies & Enterprises': 0.6,
    'Real Estate, Rental & Leasing': 0.2,
    'Mining, Quarrying and Oil/Gas Extraction': 0.8,
    'Construction': 0.4,
}

ACTOR_TYPE_SCORES = {
    'Nation-State': 1.0,
    'Criminal': 0.8,
    'Terrorist': 0.6,
    'Hacktivist': 0.4,
    'Hobbyist': 0.2,   
}


def get_score_for_threat_actor(complexity_score, veris_impact, cvss_data, frequency_score, sector, actor_type, twmratio, mitigation_ratio):
    # impact score
    avg_cvss = cvss_data['cvss'].mean()
    sophistication = veris_impact['severity'].mean()


    cvss_weight = 0.5
    impact_score =  (sophistication + (avg_cvss * cvss_weight)) / (1 + cvss_weight)
    impact_score /= 10

    print("impact score: (always lie in 1-10)")

    print("avg cvss")
    print(avg_cvss)
    
    print("Complexity Score")
    print(complexity_score)

    print("sophistication")
    print(sophistication)

    print("impact score")
    print(impact_score)
    print("---------")

    print("freq  score")
    print(frequency_score)
    print("---------")


    sector_score = sector.apply(lambda x: np.mean([SECTOR_SCORES.get(i, 0) for i in x])).mean()

    print("Sector Score")
    print(sector_score)
    print("---------")

    # actor type score

    actor_type_score = actor_type.apply(lambda x: np.mean([ACTOR_TYPE_SCORES.get(i, 0) for i in x])).mean()



    print("Actor Type Score")
    print(actor_type_score)
    print("---------")

    # mitigation score
    mitigation_score = twmratio + mitigation_ratio

    print("Mitigation Score")
    print(mitigation_score)
    print('CWE Mitigations')
    print(mitigation_ratio)

    print("---------")


    # Combine the scores using weights (or equal weights if no specific weight is given)
    total_score = (
        complexity_score * 20 + 
        frequency_score * 20 +
        impact_score * 30 +
        mitigation_score * 10 +
        sector_score * 10 +
        actor_type_score * 10
    )
    data = {
        'Score': [
            complexity_score,
            frequency_score,
            impact_score,
            mitigation_score,
            sector_score,
            actor_type_score,
            0  # Placeholder for 'Remaining' score
        ],
        'Label': [
            'Complexity Score',
            'Frequency Score',
            'Impact Score',
            'Mitigation Score',
            'Sector Score',
            'Actor Type Score',
            ''  # Label for remaining part
        ],
        'Max Weight': [
            20,
            20,
            30,
            10,
            10,
            10,
            0
            
        ]
    }

    # Create DataFrame
    df = pd.DataFrame(data)

    # Calculate weights
    df['Weight'] = df['Score'] * [20, 20, 30, 10, 10, 10, 0]  # Weight for remaining is 0 initially

    # Calculate total score
    total_score = df['Weight'].sum()

    # Update the remaining weight based on total score
    df.loc[df['Label'] == '', 'Weight'] = 100 - total_score

    print("---------")

    print(total_score)

    return total_score, df