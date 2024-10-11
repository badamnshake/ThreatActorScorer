import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from flask import Flask, jsonify, send_from_directory
from dash import Dash, dcc, html, Input, Output, State, dash_table
from veris_data import extract_veris_data, load_data as load_vd
from nist_data import extract_nist_data, load_data as load_nd
from cvwe_data import extract_cvss_data, load_data as load_cd
from group_data import get_all_groups, get_ttps_of_group, load_data as load_gd
from incident import load_data as load_incident  # Import load_data from incident.py
from actor_per_country import load_data as load_actor_per_country  # Importing actor_per_country
from geo_distribution import geo_layout, create_geo_distribution_chart
from time_series_chart import time_series_layout, create_time_series_chart 
from attack_techniques import heatmap_layout, create_heatmap_chart
from resource_utilization import resource_utilization_layout, create_resource_utilization_chart
from plotly import graph_objects as go
import os

# Cache all the data so the app is fast
load_nd()  # nist data
load_cd()  # cve data
load_vd()  # veris data
load_gd()  # group data
load_incident()  # incident data
load_actor_per_country()  # Load actor per country data

# Create Flask app and integrate it with Dash
server = Flask(__name__, static_folder='../public')  # Adjust if necessary based on directory structure
app = Dash(__name__, server=server, external_stylesheets=['https://codepen.io/chriddyp/pen/bWLwgP.css'], suppress_callback_exceptions=True)

# Function to load the processed incident data from the CSV file
def load_processed_incident_data():
    return pd.read_csv('incident_list_processed.csv')

# Function to load the processed actor per country data from the CSV file
def load_actor_per_country_data():
    # Ensure that the file path is correct and relative to your setup
    csv_path = os.path.join(os.path.dirname(__file__), '../data/actors_per_country_filled_lat_lon.csv')
    if os.path.exists(csv_path):
        return pd.read_csv(csv_path)
    else:
        print(f"File not found: {csv_path}")
        return pd.DataFrame()  # Return an empty DataFrame if file is not found

# Flask API endpoint to serve threat actor data by country, including latitude and longitude
@server.route('/actors_by_country', methods=['GET'])
def get_actors_by_country():
    print("Request received for /actors_by_country")  # Debug print
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

    html.Iframe(
        src='http://localhost:8050/public/index.html',
        style={"height": "600px", "width": "100%"}
    ),

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
        html.Div(style={'flex': '1', 'marginRight': '10px'}, children=[
            dcc.Graph(id='severity-pie-chart', style={'height': '300px'}),
        ]),
        html.Div(style={'flex': '1'}, children=[
            dcc.Graph(id='capability-pie-chart', style={'height': '300px'}),
        ]),
    ]),

    # NIST and Region Bar Charts
    html.Div(style={'display': 'flex', 'justifyContent': 'space-between'}, children=[
        html.Div(style={'flex': '1'}, children=[
            dcc.Graph(id='nist-bar-chart'),
        ]),
        html.Div(style={'flex': '1'}, children=[
            dcc.Graph(id='region-bar-chart'),
        ]),
    ]),

    # Timeline chart
    html.Div([
        dcc.Graph(id='timeline-chart', style={'height': '900px'})
    ]),

    # Geo chart
    html.Div([
        geo_layout(),
    ]),

    # Time series chart
    html.Div([
        time_series_layout(),
    ]),

    # Heatmap Chart
    html.Div([
        heatmap_layout(),
    ]),

    # Resource Utilization chart
    html.Div([
        resource_utilization_layout(),
    ]),

    # CVSS Data Table
    html.Div(id='cvss-table-container', children=[
        dash_table.DataTable(
            id='cvss-data-table',
            style_table={
                'overflowX': 'auto',
                'minWidth': '90%',
                'width': '90%',
                'maxWidth': '90%',
                'border': '1px solid black',
                'padding': '10px',
                'backgroundColor': '#f2f2f2',
                'color': '#333333',
                'fontSize': '14px',
                'fontFamily': 'Arial, sans-serif'
            },
            style_data={
                'whiteSpace': 'normal',
                'textAlign': 'left',
                'backgroundColor': '#f2f2f2',
                'color': '#333333'
            }
        )
    ]),

    # CVSS Summary Table
    html.Div(id='ttp-table-container', children=[
        dash_table.DataTable(
            id='ttp-data-table',
            style_table={
                'overflowX': 'auto',
                'minWidth': '20%',
                'maxWidth': '90%',
                'border': '1px solid black',
                'padding': '10px',
                'backgroundColor': '#f2f2f2',
                'color': '#333333',
                'fontSize': '14px',
                'fontFamily': 'Arial, sans-serif'
            },
            style_data={
                'whiteSpace': 'normal',
                'textAlign': 'left',
                'backgroundColor': '#f2f2f2',
                'color': '#333333'
            }
        )
    ]),
])


# Callback to update graphs based on TTPs input
@app.callback(
    [Output('severity-pie-chart', 'figure'),
     Output('capability-pie-chart', 'figure'),
     Output('nist-bar-chart', 'figure'),
     Output('cvss-data-table', 'data'),
     Output('ttp-data-table', 'data'),
     Output('region-bar-chart', 'figure')],
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
        cvss_data, ttp_year_summary = extract_cvss_data(ttps)  # Extract CVSS data

        # Load the processed incident data for regions
        incident_data = load_processed_incident_data()

        # Group by region to get counts for bar chart
        region_counts = incident_data['Output'].value_counts().reset_index()
        region_counts.columns = ['Region', 'Count']

        # Load the actor per country data
        actors_per_country = load_actor_per_country_data()

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

        # Create a bar chart for region-based incidents
        region_fig = px.bar(
            region_counts,
            x='Region',
            y='Count',
            title='Incident Counts by Region',
            labels={'Region': 'Region', 'Count': 'Number of Incidents'},
        )

        # Convert CVSS data into a format suitable for the DataTable
        cvss_data_table = cvss_data.to_dict('records')  # Convert to list of dictionaries

        return severity_fig, capability_fig, nist_fig, cvss_data.to_dict('records'), ttp_year_summary.to_dict('records'), region_fig,
    else:
        empty_fig = go.Figure()
        return empty_fig, empty_fig, empty_fig,[], [], empty_fig


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
    return [go.Figure(), go.Figure(), go.Figure(), [], go.Figure(), go.Figure()]
csv_file_path = r'..\data\threat_actor_groups_aliases.csv'

# Callback to update the timeline chart
@app.callback(
    Output('timeline-chart', 'figure'),
    Input('submit-button', 'n_clicks')
)
def update_timeline_chart(n_clicks):
    if n_clicks > 0:
        try:
            # Load the CSV file
            df = pd.read_csv(csv_file_path)

            # Convert 'first_seen' and 'last_seen' columns to datetime
            df['first_seen'] = pd.to_datetime(df['first_seen'])
            df['last_seen'] = pd.to_datetime(df['last_seen'])

            # Create a timeline chart using the 'name' column as the y-axis
            fig = px.timeline(df, x_start='first_seen', x_end='last_seen', y='name', title='Threat Actor Activity Timeline')
            return fig
        except FileNotFoundError:
            raise FileNotFoundError(f"CSV file not found at: {csv_file_path}")
    else:
        # Return an empty figure if no clicks yet
        return go.Figure()
    
#Geo callback
def geo_layout():
    return html.Div([
        dcc.Graph(id='geo-distribution-chart'),  # Ensure this ID matches what you're using
        # Other components can be added here as needed
    ])

def register_callbacks(app):
    @app.callback(
        Output('geo-distribution-chart', 'figure'),
        Input('some-input', 'value')
    )
    def update_geo_chart(input_value):
        print(f'Input value received: {input_value}')  # Log input value
        # Return a figure or empty figure for debugging
        return {}
# Callback to update the geo chart
@app.callback(
    Output('geo-distribution-chart', 'figure'),
    Input('submit-button', 'n_clicks')  # You can trigger this with any relevant input
)
def update_geo_chart(n_clicks):
    # Call the function to create the geo chart
    return create_geo_distribution_chart()

# Callback to update the time series chart
@app.callback(
    Output('time-series-chart', 'figure'),
    Input('submit-button', 'n_clicks')  # Modify if needed for specific interactions
)
def update_time_series_chart(n_clicks):
    if n_clicks > 0:
        return create_time_series_chart()  # Create the time series chart
    return create_time_series_chart()  # Return the chart by default

# Callback to create the heatmap chart
@app.callback(
    Output('heatmap-chart', 'figure'),
    Input('submit-button', 'n_clicks')  # Modify if needed for specific interactions
)
def update_heatmap_chart(n_clicks):
    if n_clicks > 0:
        return create_heatmap_chart()  # Create the heatmap chart
    return create_heatmap_chart()  # Return the chart by default

# Callback to create the resource utilization chart
@app.callback(
    Output('resource-utilization-chart', 'figure'),
    Input('submit-button', 'n_clicks')  # Adjust according to your buttons/input
)
def update_resource_utilization(n_clicks):
    if n_clicks > 0:  # Trigger the update on button click
        return create_resource_utilization_chart()
    return create_resource_utilization_chart()  # Default chart on load



if __name__ == '__main__':
    app.run_server(debug=True, port=8050)
