
# calculate score from mathematical formula
def get_score(capability, frequency, cvss, industry):
    return capability + frequency + cvss + industry
# given a dataset fetch the variables required to get a score
def get_score_using_datasets(severity_counts, incident_data, cvss):
    return 100

