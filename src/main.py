import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from dash import Dash, dcc, html, Input, Output, State, dash_table
from veris_data import extract_veris_data, load_data as load_vd
from nist_data import extract_nist_data, load_data as load_nd
from cvwe_data import extract_cvss_data, load_data as load_cd
from group_data import get_all_groups, get_ttps_of_group, load_data as load_gd  # Adjust import according to your file structure

# cache all the data so the app is fast::
load_nd() # nist data
load_cd() # cve data
load_vd() # veris data
load_gd() # group data

# Create the Dash app
app = Dash(__name__, external_stylesheets=['https://codepen.io/chriddyp/pen/bWLwgP.css'])


# Initial layout for the app
app.layout = html.Div(style={'fontFamily': 'Arial, sans-serif', 'margin': '20px'}, children=[
    html.H1(children='Threat Actor Analysis', style={'textAlign': 'center', 'color': '#4B0082'}),

    html.Div(style={'display': 'flex', 'justifyContent': 'center', 'alignItems': 'center', 'marginBottom': '20px'}, children=[
        dcc.Dropdown(
            id='group-id-dropdown',
            options=[{'label': group, 'value': group} for group in get_all_groups()],
            placeholder='Select a Group ID',
            style={'width': '30%', 'marginRight': '10px'}
        ),
        dcc.Input(
            id='ttp-input',
            type='text',
            value = '',
            placeholder='Enter TTPs (comma-separated)',
            style={'width': '70%', 'height': '40px', 'fontSize': '16px'}
        ),
        html.Button('Submit', id='submit-button', n_clicks=0, style={
            'marginLeft': '10px', 'backgroundColor': '#4CAF50', 'color': 'white',
            'border': 'none', 'padding': '10px 20px', 'cursor': 'pointer'
        }),
    ]),

    html.Div(style={'display': 'flex', 'justifyContent': 'space-between'}, children=[
        html.Div(style={'flex': '1', 'marginRight': '10px'}, children=[
            dcc.Graph(id='severity-pie-chart', style={'height': '300px'}),
        ]),
        html.Div(style={'flex': '1'}, children=[

            dcc.Graph(id='capability-pie-chart', style={'height': '300px'}),
            # dcc.Graph(id='nist-bar-chart', style={'height': '300px'}),
        ]),
    ]),

    html.Div(style={'display': 'flex', 'justifyContent': 'space-between'}, children=[
        html.Div(style={'flex': '1'}, children=[
            dcc.Graph(id='nist-bar-chart'),
        ]),
    ]),

    # New table for CVSS data
    html.Div(id='cvss-table-container', children=[
        dash_table.DataTable(id='cvss-data-table', style_table={'overflowX': 'auto'})
    ])
])

# Callback to update graphs based on TTPs input
@app.callback(
    [Output('severity-pie-chart', 'figure'),
     Output('capability-pie-chart', 'figure'),
     Output('nist-bar-chart', 'figure'),
     Output('cvss-data-table', 'data')],
    Input('submit-button', 'n_clicks'),
    State('ttp-input', 'value')
)
def update_graphs(n_clicks, ttps_input):
    if n_clicks > 0 and ttps_input:
        # Split the input string into a list of TTPs
        ttps = [ttp.strip() for ttp in ttps_input.split(',')]

        # Call the extract functions
        _, severity_counts, capability_counts = extract_veris_data(ttps)
        nist_violations = extract_nist_data(ttps)
        cvss_data = extract_cvss_data(ttps)  # Extract CVSS data

        # Create pie charts for severity counts
        severity_colors = ['#00FF00', '#FFFF00', '#FFA500', '#FF0000']  # Green, Yellow, Orange, Red
        severity_fig = px.pie(
            names=severity_counts['severity_level'],
            values=severity_counts['count'],
            title='Techniques Rated',
            color=severity_counts.index,
            color_discrete_sequence=severity_colors
        )

        # Create a pie chart for capability counts
        capability_fig = px.pie(
            capability_counts,
            names='capability_group',
            values='capability_id',
            title='CIA Triad Capability Counts',
            color_discrete_sequence=['#FF9999', '#66B3FF', '#99FF99']  # Custom colors
        )

        # Create a bar chart for NIST violations
        nist_fig = px.bar(
            nist_violations,
            x='capability_id',
            y='capability_group',
            title='NIST Violations by Type',
            labels={'capability_id': 'Violations', 'capability_group': 'Type'},
        )

        # Convert CVSS data into a format suitable for the DataTable
        cvss_data_table = cvss_data.to_dict('records')  # Convert to list of dictionaries

        return severity_fig, capability_fig, nist_fig, cvss_data_table
    else:
        empty_fig = go.Figure()
        return empty_fig, empty_fig, empty_fig, []


# New callback to update TTP input based on selected group
@app.callback(
    Output('ttp-input', 'value'),
    Input('group-id-dropdown', 'value')
)
def update_ttp_input(selected_group):
    if selected_group:
        ttps = get_ttps_of_group(selected_group)
        return ', '.join(ttps) if isinstance(ttps, list) else ''
    return ''

# Run the app
if __name__ == '__main__':
    app.run_server(debug=True)
