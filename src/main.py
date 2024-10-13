import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from flask import Flask, jsonify, send_from_directory
from dash import Dash, dcc, html, Input, Output, State
from veris_data import extract_veris_data, load_data as load_vd
from nist_data import extract_nist_data, load_data as load_nd
from cvwe_data import load_data as load_cd, extract_cvss_scores
from group_data import get_all_groups, get_ttps_of_group, get_group_incidents, load_data as load_gd
# from actor_per_country import load_data as load_actor_per_country  # Importing actor_per_country
from plotly import graph_objects as go
from incident import load_processed_incident_data, load_actor_per_country_data

# Cache all the data so the app is fast
load_nd()  # nist data
load_cd()  # cve data
load_vd()  # veris data
load_gd()  # group data
# load_actor_per_country()  # Load actor per country data

# Create Flask app and integrate it with Dash
server = Flask(__name__, static_folder='../public')  # Adjust if necessary based on directory structure
app = Dash(__name__, server=server, external_stylesheets=['https://codepen.io/chriddyp/pen/bWLwgP.css'], suppress_callback_exceptions=True)


# Flask API endpoint to serve threat actor data by country, including latitude and longitude
@server.route('/actors_by_country', methods=['GET'])
def get_actors_by_country():
    # print("Request received for /actors_by_country")  # Debug print
    # Load actor data
    actor_data = load_actor_per_country_data()

    # Prepare the data to be returned as JSON
    data = []
    for index, row in actor_data.iterrows():
        country = row['country']
        latitude = row['latitude']
        longitude = row['longitude']
        
        # Validate if latitude and longitude are numbers
        if pd.notna(latitude) and pd.notna(longitude):
            latitude = float(latitude)
            longitude = float(longitude)

            # Only include valid entries
            actor_list = row['actor_list'].split(',')  # Ensure actors are a list
            data.append({
                'country': country,
                'latitude': latitude,
                'longitude': longitude,
                'actors': actor_list
            })

    # Return JSON response
    return jsonify(data)

# Serve the index.html file
@server.route('/public/<path:path>')
def serve_static_files(path):
    return send_from_directory('../public', path)


# Initial layout for the Dash app
app.layout = html.Div(style={'fontFamily': 'Arial, sans-serif', 'margin': '20px'}, children=[
    html.H1(children='Threat Actor Analysis', style={'textAlign': 'center', 'color': '#4B0082'}),
    html.Iframe(src='http://localhost:8050/public/index.html', style={"height": "600px", "width": "100%"}),
    
    # Dropdown and input field for TTPs
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
            value='',
            placeholder='Enter TTPs (comma-separated)',
            style={'width': '70%', 'height': '40px', 'fontSize': '16px'}
        ),
        html.Button('Submit', id='submit-button', n_clicks=0, style={
            'marginLeft': '10px', 'backgroundColor': '#4CAF50', 'color': 'white',
            'border': 'none', 'padding': '10px 20px', 'cursor': 'pointer'
        }),
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
])


# Callback to update graphs based on TTPs input
@app.callback(
    [Output('severity-pie-chart', 'figure'),
     Output('capability-pie-chart', 'figure'),
     Output('nist-bar-chart', 'figure'),
     Output('incidents', 'figure'),
     Output('attack-geo', 'figure'),
     Output('cvss-scatter', 'figure')
     ],
    Input('submit-button', 'n_clicks'),
    State('ttp-input', 'value'),
    State('group-id-dropdown', 'value')
)
def update_graphs(n_clicks, ttps_input, group_id):
    if n_clicks > 0 and ttps_input:
        # Split the input string into a list of TTPs
        ttps = [ttp.strip() for ttp in ttps_input.split(',')]

        # Call the extract functions
        _, severity_counts, capability_counts = extract_veris_data(ttps)
        nist_violations = extract_nist_data(ttps)
        cvss_scores = extract_cvss_scores(ttps)  # Extract CVSS data
        # print(cvss_scores)

        # Load the processed incident data for regions
        incident_data = load_processed_incident_data()

        # Group by region to get counts for bar chart
        region_counts = incident_data['Output'].value_counts().reset_index()
        region_counts.columns = ['Region', 'Count']


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
            labels={'capability_id': 'Violatons', 'capability_group': 'Type'},
        )

        gf = get_group_incidents(group_id)
        # print(gf)

        incidents = px.scatter(
            gf,
            x='event_date',
            y='industry',
            color='motive',
            symbol='motive',
            hover_name='description',
            title='News articles by date and industry',
            labels={'industry': 'Industry','event_date': 'Event Date' }
        )
        incidents.update_layout(scattermode="group", scattergap=0.75)

        cvss_scores_scatter = px.scatter(
            cvss_scores,
            x='year',
            y='cvss',
            color='severity',
            symbol='severity',
            hover_name='cve',
            title='CVE\'s the threat actor exploits with regards to their cvss',
            labels={'year': 'Year','cvss': 'CVSS Score' }
        )

        cvss_scores_scatter.update_layout(scattermode="group", scattergap=0.75)
        cvss_scores_scatter.update_xaxes(autorange='reversed')


        # print(gf)
        # Create the scatter geo plot
        attack_geo = px.scatter_geo(
            gf,
            locations='country',  # Use country names directly
            locationmode='country names',
            size=[3] * len(gf),  # Constant size for all bubbles
            hover_name='description',  # Description displayed on hover
            color='country',  # Optional: color by country
            opacity=0.6,
            title='Scatter Geo Plot of Events by Country',
            labels={'country': 'Country'},
        )

        return severity_fig, capability_fig, nist_fig, incidents, attack_geo, cvss_scores_scatter
    else:
        empty_fig = go.Figure()
        return empty_fig, empty_fig, empty_fig,empty_fig, empty_fig, empty_fig


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

if __name__ == '__main__':
    app.run_server(debug=True, port=8050)
