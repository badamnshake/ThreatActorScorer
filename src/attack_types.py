import pandas as pd
import plotly.express as px
import plotly.graph_objects as go  # Importing go to create an empty figure
from dash import dcc, html
from pathlib import Path

# Load the attack mapping data
base_path = Path(__file__).resolve().parent.parent
veris_df = pd.read_csv(base_path / 'data/veris_attack_mapping.csv')

# Create a function to generate the pie chart
def create_attack_type_pie_chart(selected_group, ttp_input):
    # Load the NIST 800-53 mapping data
    base_path = Path(__file__).resolve().parent.parent
    attack_mapping_df = pd.read_csv(base_path / 'data/nist_800_53_mapping.csv')

    # Filter data based on the TTP input
    if ttp_input:
        ttp_ids = [x.strip() for x in ttp_input.split(',')]
        attack_mapping_df = attack_mapping_df[attack_mapping_df['attack_object_id'].isin(ttp_ids)]

    # Count occurrences of each attack type
    attack_type_counts = attack_mapping_df['attack_object_name'].value_counts().reset_index()
    attack_type_counts.columns = ['Attack_Type', 'Count']

    # Create pie chart
    figure = px.pie(attack_type_counts, names='Attack_Type', values='Count',
                    title='Distribution of Attack Types')

    return figure
# Layout for the pie chart
attack_type_layout = dcc.Graph(id='attack-type-pie-chart')
