# main.py
from dash import Dash, dcc, html, Input, Output, State
import plotly.express as px
import pandas as pd
from veris_data import extract_veris_data

# Create the Dash app
app = Dash(__name__)

# Initial layout for the app
app.layout = html.Div(children=[
    html.H1(children='VERIS Data Analysis'),

    html.Label("Enter TTPs (comma-separated):"),
    dcc.Input(id='ttp-input', type='text', placeholder='e.g. T1136, T1133, T1543'),

    html.Button('Submit', id='submit-button', n_clicks=0),

    dcc.Graph(id='severity-pie-chart'),
    dcc.Graph(id='capability-pie-chart')
])

# Callback to update graphs based on TTPs input
@app.callback(
    [Output('severity-pie-chart', 'figure'),
     Output('capability-pie-chart', 'figure')],
    Input('submit-button', 'n_clicks'),
    State('ttp-input', 'value')
)
def update_graphs(n_clicks, ttps_input):
    if n_clicks > 0 and ttps_input:
        # Split the input string into a list of TTPs
        ttps = [ttp.strip() for ttp in ttps_input.split(',')]

        # Call the extract function to get the data based on TTPs
        average_severity, severity_counts, capability_counts = extract_veris_data(ttps)

        # Create a pie chart for severity counts
        severity_colors = ['#00FF00', '#FFFF00', '#FFA500', '#FF0000']  # Green, Yellow, Orange, Red
        severity_fig = px.pie(
            names=severity_counts.index,
            values=severity_counts.values,
            title='Severity Levels',
            color=severity_counts.index,
            color_discrete_sequence=severity_colors
        )

        # Rename capability groups to CIA triad
        capability_counts['capability_group'] = capability_counts['capability_group'].replace({
            'Integrity': 'Confidentiality',  # Adjust as needed
            'Availability': 'Availability',
            'Confidentiality': 'Integrity'
        })

        # Create a pie chart for capability counts with specific colors
        capability_fig = px.pie(
            capability_counts,
            names='capability_group',
            values='capability_id',
            title='CIA Triad Capability Counts',
            color_discrete_sequence=['#FF9999', '#66B3FF', '#99FF99']  # Custom colors
        )

        return severity_fig, capability_fig
    else:
        # Return empty figures if no input has been provided
        return {}, {}

# Run the app
if __name__ == '__main__':
    app.run_server(debug=True)
