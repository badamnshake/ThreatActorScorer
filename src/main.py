import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from flask import Flask, jsonify, send_from_directory
from dash import Dash, dcc, html, Input, Output, State
from veris_data import extract_veris_data, load_data as load_vd
from nist_data import extract_nist_data, load_data as load_nd
from cvwe_data import load_data as load_cd, extract_cvss_scores
from group_data import get_all_groups, get_ttps_of_group, get_group_incidents, load_data as load_gd
from incident import load_processed_incident_data, load_actor_per_country_data
from scorer import get_score_using_datasets, get_score
from time_series_chart import time_series_layout, create_time_series_chart
from first_last_seen_chart import create_first_last_seen_chart  # Adjust based on your file structure
from ttp_heatmap import load_complexity_scores, create_ttp_heatmap
from ttp_complexity_chart import create_ttp_complexity_chart, load_complexity_scores
from pathlib import Path
import numpy as np

# Cache all the data so the app is fast
load_nd()  # NIST data
load_cd()  # CVE data
load_vd()  # VERIS data
load_gd()  # Group data
# Sample selected TTPs (this would come from a dropdown or input in your actual app)
selected_ttps = ['T1548', 'T1548.002', 'T1548.004']


# Create Flask app and integrate it with Dash
server = Flask(__name__, static_folder='../public')  # Adjust if necessary based on directory structure
app = Dash(__name__, server=server, 
            external_stylesheets=['https://codepen.io/chriddyp/pen/bWLwgP.css'], 
            suppress_callback_exceptions=True)

# Flask API endpoint to serve threat actor data by country
@server.route('/actors_by_country', methods=['GET'])
def get_actors_by_country():
    actor_data = load_actor_per_country_data()
    data = [
        {
            'country': row['country'],
            'latitude': float(row['latitude']),
            'longitude': float(row['longitude']),
            'actors': row['actor_list'].split(',') if pd.notna(row['actor_list']) else []
        }
        for _, row in actor_data.iterrows()
        if pd.notna(row['latitude']) and pd.notna(row['longitude'])
    ]
    return jsonify(data)

#heatmap
def create_ttp_heatmap(data):
    # Create a heatmap using the provided data
    heatmap_fig = go.Figure(data=go.Heatmap(
        z=data['New_Complexity_Score'].values.reshape(1, -1),  # Reshape for heatmap
        x=data['ID'].values,
        colorscale='Viridis',
    ))
    heatmap_fig.update_layout(title='TTP Complexity Scores Heatmap')
    return heatmap_fig

def generate_heatmap(selected_ttps):
    filtered_data = load_complexity_scores(selected_ttps)
    heatmap_fig = go.Figure()  # Initialize heatmap_fig with an empty figure

    if not filtered_data.empty:
        heatmap_fig = create_ttp_heatmap(filtered_data)  # Use the filtered data to create the heatmap
    else:
        # Create a heatmap with all selected TTPs, showing 0 if they don't exist in the CSV
        missing_ttps = set(selected_ttps) - set(filtered_data['ID'])
        for ttp in missing_ttps:
            filtered_data = filtered_data.append({'ID': ttp, 'New_Complexity_Score': 0}, ignore_index=True)
        heatmap_fig = create_ttp_heatmap(filtered_data)  # Pass the updated filtered_data

    return heatmap_fig

# Serve static files
@server.route('/public/<path:path>')
def serve_static_files(path):
    return send_from_directory('../public', path)

# Initial layout for the Dash app
app.layout = html.Div(style={'fontFamily': 'Arial, sans-serif', 'margin': '20px'}, children=[
    html.H1(children='Threat Actor Analysis', style={'textAlign': 'center', 'color': '#4B0082'}),
    html.Iframe(src='http://localhost:8050/public/index.html', style={"height": "600px", "width": "100%"}),
    
    # Dropdown and input field for TTPs
    html.Div(style={'display': 'flex', 'justifyContent': 'space-between', 'alignItems': 'center', 'marginBottom': '20px'}, children=[
        
        dcc.Dropdown(
            id='group-id-dropdown',
            options=[{'label': group, 'value': group} for group in get_all_groups()],
            placeholder='Select a Group ID',
            style={'min-width': '30%','marginRight': '10px'}
        ),
        dcc.Input(
            id='ttp-input',
            type='text',
            value='',
            placeholder='Enter TTPs (comma-separated)',
            style={ 'min-width': '60%'}
        ),
        html.Button('Submit', id='submit-button', n_clicks=0, style={
            'marginLeft': '10px', 'backgroundColor': '#4CAF50', 'color': 'white',
             'cursor': 'pointer'
        }),
    ]),

    html.Div([time_series_layout()]),
 # New layout for the First Seen and Last Seen chart
    html.Div(id='first-last-seen-chart-container', children=[
        dcc.Graph(id='first-last-seen-chart'),
    ]),

    #New Layout for heatmap
    html.Div([
    dcc.Graph(id='ttp-heatmap', figure=go.Figure())  # Initialize with an empty figure
]),

# New layout for TTP complexity bar chart
    html.Div([
        dcc.Graph(id='ttp-complexity-bar-chart', figure=go.Figure())  # Initialize with an empty figure
    ]),



    # Severity and Capability Pie Charts
    html.Div(style={'display': 'flex', 'justifyContent': 'space-between'}, children=[
        dcc.Graph(id='severity-pie-chart', style={'flex': '1', 'marginRight': '10px'}),
        dcc.Graph(id='capability-pie-chart', style={'flex': '1'}),
    ]),

    dcc.Graph(id='incidents'),
    dcc.Graph(id='attack-geo'),
    dcc.Graph(id='cvss-scatter'),
    dcc.Graph(id='nist-bar-chart'),

    # Dropdown and input field for TTPs
    html.Div(style={'display': 'flex', 'justifyContent': 'space-between', 'alignItems': 'center', 'marginBottom': '20px'}, children=[

        dcc.Input(
            id='score-capability',
            type='text',
            value='',
            placeholder='Enter Capability (0-10)',
            style={ 'min-width': '20%'}
        ),
        
        dcc.Input(
            id='score-frequency',
            type='text',
            value='',
            placeholder='Enter Incident Numbers (0 - n)',
            style={ 'min-width': '20%'}
        ),

        dcc.Input(
            id='score-industry',
            type='text',
            value='',
            placeholder='Enter Industry of Threat Actor',
            style={ 'min-width': '20%'}
        ),

        dcc.Input(
            id='score-violations',
            type='text',
            value='',
            placeholder='Enter NIST Violations',
            style={ 'min-width': '20%'}
        ),

        html.Button('Calculate Score Manually', id='update-score-button', n_clicks=0, style={
            'marginLeft': '10px', 'backgroundColor': '#4CAF50', 'color': 'white',
             'cursor': 'pointer'
        }),
    ]),

    html.H1(id='score-display', children='Score: 0'),
])
# Callback to update time series chart based on selected threat actor
@app.callback(
    Output('time-series-chart', 'figure'),
    Input('submit-button', 'n_clicks'),
    State('group-id-dropdown', 'value')  
)
def update_time_series_chart(n_clicks, selected_actor):
    if n_clicks > 0 and selected_actor:
        # Pass the selected actor to your time series chart creation function
        return create_time_series_chart(selected_actor)  # Modify this function to filter data based on the actor
    return create_time_series_chart()  # Return the default chart if no actor is selected

# Callback for the first and last seen chart
@app.callback(
    Output('first-last-seen-chart', 'figure'),
    Input('group-id-dropdown', 'value')
)
def update_first_last_seen(selected_actor):
    return create_first_last_seen_chart(selected_actor)  # Pass the selected actor to the function

#call back for heatmap
@app.callback(
    Output('ttp-heatmap', 'figure'),  # Ensure the ID matches your layout
    Input('submit-button', 'n_clicks'),
    State('ttp-input', 'value'),
    State('group-id-dropdown', 'value')
)
def update_heatmap(n_clicks, ttps_input, group_id):
    if n_clicks > 0:
        ttps = [ttp.strip() for ttp in ttps_input.split(',')]
        return generate_heatmap(ttps)  # Call to generate_heatmap with the TTPs
    return go.Figure()  # Return an empty figure if no button clicks

# Callback to bar chart
base_path = Path(__file__).resolve().parent.parent
complexity_df = pd.read_csv(base_path / 'data/Techniques_with_Complexity_Scores_New.csv')

@app.callback(
    Output('ttp-complexity-bar-chart', 'figure'),
    [Input('group-id-dropdown', 'value'),  # Adjust input as needed
     Input('ttp-input', 'value')]  # Assuming you're using the TTP input to update the chart
)

def update_ttp_complexity_bar_chart(selected_group, ttp_input):
    # Example data processing based on the selected group and TTP input
    if selected_group and ttp_input:
        ttp_ids = [x.strip() for x in ttp_input.split(',')]
        
        # Use the already loaded complexity_df
        # Filter based on selected TTP IDs if necessary
        filtered_df = complexity_df[complexity_df['ID'].isin(ttp_ids)]
        
        # Fill N/A for hover data in 'sub-technique of' column
        filtered_df['sub-technique of'] = filtered_df['sub-technique of'].fillna('N/A')
        
        # Create the bar chart with color scale based on 'Complexity_Score'
        figure = px.bar(
            filtered_df,
            x='ID',
            y='Complexity_Score',
            color='Complexity_Score',
            color_continuous_scale=px.colors.sequential.Viridis_r,
            hover_data={
                'ID': True,
                'Complexity_Score': True,
                'name': True,
                'tactics': True,
                'sub-technique of': True  # Directly use the modified column
            }
        ) 

        figure.update_layout(
            title='TTP Complexity Scores',
            xaxis_title='TTP ID',
            yaxis_title='Complexity Score',
        )
        
        return figure
    else:
        # Return an empty figure if no valid input is provided
        return go.Figure()

# Callback to update graphs based on TTPs input
@app.callback(
    [Output('severity-pie-chart', 'figure'),
     Output('capability-pie-chart', 'figure'),
     Output('nist-bar-chart', 'figure'),
     Output('incidents', 'figure'),
     Output('attack-geo', 'figure'),
     Output('cvss-scatter', 'figure'),
     Output('score-display', 'children')],
    Input('submit-button', 'n_clicks'),
    State('ttp-input', 'value'),
    State('group-id-dropdown', 'value')
)
def update_graphs(n_clicks, ttps_input, group_id):
    if n_clicks > 0 and ttps_input:
        # Process TTPs input
        ttps = [ttp.strip() for ttp in ttps_input.split(',')]

        # Extract data
        _, severity_counts, capability_counts = extract_veris_data(ttps)
        nist_violations = extract_nist_data(ttps)
        cvss_scores = extract_cvss_scores(ttps)
        incident_data = load_processed_incident_data()

        score = get_score_using_datasets(severity_counts, incident_data, cvss_scores)
        print(score)

        

        # Prepare data for figures
        severity_fig = create_severity_pie_chart(severity_counts)
        capability_fig = create_capability_pie_chart(capability_counts)
        nist_fig = create_nist_bar_chart(nist_violations)
        incidents_fig = create_incidents_scatter_plot(group_id, incident_data)
        attack_geo_fig = create_attack_geo_plot(group_id)
        cvss_scores_fig = create_cvss_scatter_plot(cvss_scores)

        return severity_fig, capability_fig, nist_fig, incidents_fig, attack_geo_fig, cvss_scores_fig, f"Score: {score}"
    else:
        return go.Figure(), go.Figure(), go.Figure(), go.Figure(), go.Figure(), go.Figure(), ""  # Return empty figures for all outputs

# New callback to update scores from manual entry
@app.callback(
    Output('score-display', 'children', allow_duplicate=True),
    Input('update-score-button', 'n_clicks'),
    
    State('score-capability', 'value'),
    State('score-frequency', 'value'),
    State('score-industry', 'value'),
    State('score-violations', 'value'),
    prevent_initial_call=True
    
)
def update_score(n_clicks, c, f, i, v):
    value = 0
    if(n_clicks > 0 and c and f and i and v):
        value = get_score(c, f, v, i)
    return f"Score: {value}"

    

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


    

def create_severity_pie_chart(severity_counts):
    """Create a pie chart for severity counts."""
    severity_colors = ['#00FF00', '#FFFF00', '#FFA500', '#FF0000']  # Green, Yellow, Orange, Red
    return px.pie(
        names=severity_counts['severity_level'],
        values=severity_counts['count'],
        title='Techniques Rated',
        color=severity_counts.index,
        color_discrete_sequence=severity_colors
    )

def create_capability_pie_chart(capability_counts):
    """Create a pie chart for capability counts."""
    return px.pie(
        capability_counts,
        names='capability_group',
        values='capability_id',
        title='CIA Triad Capability Counts',
        color_discrete_sequence=['#FF9999', '#66B3FF', '#99FF99']
    )

def create_nist_bar_chart(nist_violations):
    """Create a bar chart for NIST violations."""
    return px.bar(
        nist_violations,
        x='capability_id',
        y='capability_group',
        title='NIST Violations by Type',
        labels={'capability_id': 'Violations', 'capability_group': 'Type'},
    )

def create_incidents_scatter_plot(group_id, incident_data):
    """Create a scatter plot for incidents."""
    gf = get_group_incidents(group_id)
    return px.scatter(
        gf,
        x='event_date',
        y='industry',
        color='motive',
        symbol='motive',
        hover_name='description',
        title='News Articles by Date and Industry',
        labels={'industry': 'Industry', 'event_date': 'Event Date'}
    ).update_layout(scattermode="group", scattergap=0.75)

def create_attack_geo_plot(group_id):
    """Create a geographic scatter plot of attack incidents."""
    gf = get_group_incidents(group_id)
    return px.scatter_geo(
        gf,
        locations='country',
        locationmode='country names',
        size=[3] * len(gf),
        hover_name='description',
        color='country',
        opacity=0.6,
        title='Scatter Geo Plot of Events by Country',
        labels={'country': 'Country'},
    )

def create_cvss_scatter_plot(cvss_scores):
    """Create a scatter plot for CVSS scores."""
    return px.scatter(
        cvss_scores,
        x='year',
        y='cvss',
        color='severity',
        symbol='severity',
        hover_name='cve',
        title='CVEs Exploited by Threat Actors',
        labels={'year': 'Year', 'cvss': 'CVSS Score'}
    ).update_layout(scattermode="group", scattergap=0.75).update_xaxes(autorange='reversed')

if __name__ == '__main__':
    app.run_server(debug=True, port=8050)