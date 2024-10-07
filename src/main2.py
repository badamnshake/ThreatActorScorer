# pip install mitreattack-python
# pip install dash

# pip install mitreattack-python
# pip install dash

from dash import Dash, html, dcc, callback, Output, Input
import plotly.express as px
import pandas as pd
from incident import process_incident_data
from data_processor import DataProcessor

# Initialize the DataProcessor
processor = DataProcessor(
    mitre_attack_path="./data/enterprise-attack.json",
    nist_path='./data/nist_800_53_mapping.csv',
    cve_path='./data/cve_mapping.csv',
    veris_path='./data/veris_attack_mapping.csv',
    cwe_path='./data/cve_to_cwe.xlsx',
 #   incidents_path='./data/cyber_operations_incidents.csv'
)

# Define the file paths
incidents_path='./data/cyber_operations_incidents.csv'
new_processed_file_path = "./data/incident_list_processed_v2.csv"  # New file name for saving processed CSV

# Call the function with the file path
process_incident_data(incidents_path)

# Load the processed CSV file
processed_file_path = 'incident_list_processed.csv'  # The file produced by incident.py

# Read the processed CSV file
processed_df = pd.read_csv(processed_file_path)

# Display the processed data (prints the first few rows)
print("Processed Data:")
print(processed_df.head())

# Save the processed data into a new file
processed_df.to_csv(new_processed_file_path, index=False)
print(f"Processed data saved to {new_processed_file_path}")

# Example group IDs for dropdown options
group_ids = list(processor.groups_dict.keys())

app = Dash()

app.layout = [
    html.H1(children='Threat Actor Scorer App', style={'textAlign': 'center'}),
    html.P(children="Explore threat actor data based on group ID."),
    dcc.Dropdown(
        options=[{'label': gid, 'value': gid} for gid in group_ids],
        value=group_ids[0],  # Default value
        id='dropdown-selection'
    ),
    dcc.Graph(id='nist-violations'),
    dcc.Graph(id='cve-violations'),
    dcc.Graph(id='cve-severity'),
    dcc.Graph(id='veris-data')
]

@callback(
    [Output('nist-violations', 'figure'),
     Output('cve-violations', 'figure'),
     Output('cve-severity', 'figure'),
     Output('veris-data', 'figure')],
    Input('dropdown-selection', 'value')
)
def update_graphs(group_id):
    # Process data for the selected group ID
    nistviolations, cve_violations, cve_severity, veris_df = processor.analyze_group(group_id)
    
    # NIST Violations Bar Graph
    if not nistviolations.empty:
        nist_fig = px.bar(nistviolations, x='capability_group', y='capability_id',
                          title=f'NIST Violations for Group {group_id}',
                          labels={'capability_id': 'Number of Violations'})
    else:
        nist_fig = px.bar(title=f'No NIST Violations data available for Group {group_id}')
    
    # CVE Violations Bar Graph
    if not cve_violations.empty:
        cve_violations_fig = px.bar(cve_violations, x='mapping_type', y='capability_id',
                                    title=f'CVE Violations for Group {group_id}',
                                    labels={'capability_id': 'Number of CVEs'})
    else:
        cve_violations_fig = px.bar(title=f'No CVE Violations data available for Group {group_id}')
    
    # CVE Severity Bar Graph
    if not cve_severity.empty:
        cve_severity_fig = px.bar(cve_severity, x='severity', y='capability_id',
                                  title=f'CVE Severity for Group {group_id}',
                                  labels={'capability_id': 'Number of CVEs'})
    else:
        cve_severity_fig = px.bar(title=f'No CVE Severity data available for Group {group_id}')
    
    # VERIS Data Bar Graph
    if not veris_df.empty:
        veris_fig = px.bar(veris_df, x='capability_group', y='capability_id',
                           title=f'Veris Data for Group {group_id}',
                           labels={'capability_id': 'Number of Attacks'})
    else:
        veris_fig = px.bar(title=f'No VERIS data available for Group {group_id}')
    
    return nist_fig, cve_violations_fig, cve_severity_fig, veris_fig

if __name__ == '__main__':
    app.run_server(debug=True)