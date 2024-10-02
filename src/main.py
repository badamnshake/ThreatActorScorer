import plotly.express as px
import pandas as pd
from dash import Dash, dcc, html, Input, Output, State
from veris_data import extract_veris_data
from nist_data import extract_nist_data
from group_data import get_all_groups, get_ttps_of_group  # Adjust import according to your file structure

# Create the Dash app
app = Dash(__name__)

# Custom CSS for styling
app.css.append_css({
    'external_url': 'https://codepen.io/chriddyp/pen/bWLwgP.css'
})

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
    ])
])

# Callback to update graphs based on TTPs input
@app.callback(
    [Output('severity-pie-chart', 'figure'),
     Output('capability-pie-chart', 'figure'),
     Output('nist-bar-chart', 'figure')],
    Input('submit-button', 'n_clicks'),
    State('ttp-input', 'value')
)
def update_graphs(n_clicks, ttps_input):
    if n_clicks > 0 and ttps_input:
        # Split the input string into a list of TTPs
        ttps = [ttp.strip() for ttp in ttps_input.split(',')]

        # Call the extract function to get the data based on TTPs
        average_severity, severity_counts, capability_counts = extract_veris_data(ttps)
        nist_violations = extract_nist_data(ttps)

        # Create a pie chart for severity counts
        severity_colors = ['#00FF00', '#FFFF00', '#FFA500', '#FF0000']  # Green, Yellow, Orange, Red
        severity_fig = px.pie(
            names=severity_counts['severity_level'],
            values=severity_counts['count'],
            title='Severity Levels',
            color=severity_counts.index,
            color_discrete_sequence=severity_colors
        )

        # Rename capability groups to CIA triad
        # capability_counts['capability_group'] = capability_counts['capability_group'].replace({
        #     'Integrity': 'Confidentiality',  # Adjust as needed
        #     'Availability': 'Availability',
        #     'Confidentiality': 'Integrity'
        # })

        # Create a pie chart for capability counts with specific colors
        capability_fig = px.pie(
            capability_counts,
            names='capability_group',
            values='capability_id',
            title='CIA Triad Capability Counts',
            color_discrete_sequence=['#FF9999', '#66B3FF', '#99FF99']  # Custom colors
        )

        nist_fig = px.bar(
            nist_violations,
            x='capability_id',
            y='capability_group',
            title='NIST Violations by Type',
            labels={'capability_id': 'Violations', 'capability_group': 'Type'},
        )

        return severity_fig, capability_fig, nist_fig
    else:
        # Return empty figures if no input has been provided
        return {}, {}, {}

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
