import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
from dash import Dash, dcc, html, Input, Output, State
from group_data import load_data, get_all_groups, get_ttps_of_group, get_group_incidents
from analysis import create_severity_pie_chart, create_capability_pie_chart, create_nist_bar_chart, create_incidents_scatter_plot, create_attack_geo_plot, create_cvss_scatter_plot, create_ttp_complexity_bar_chart
from veris_data import extract_veris_data
from nist_data import extract_nist_data
from cvwe_data import extract_cvss_scores
from incident import load_actor_per_country_data

# Load the data before setting up the app
load_data()

# Create Flask app and integrate it with Dash
server = Flask(__name__, static_folder='../public')
CORS(server)

app = Dash(__name__, server=server, 
           external_stylesheets=['https://codepen.io/chriddyp/pen/bWLwgP.css'], 
           suppress_callback_exceptions=True)

# Serve static files like the Cesium globe page
@server.route('/public/<path:path>')
def serve_static_files(path):
    return send_from_directory('../public', path)

# Flask API endpoint to serve threat actor data by country
@server.route('/actors_by_country', methods=['GET'])
def get_actors_by_country():
    actor_data = load_actor_per_country_data()  # Ensure the data is loaded from the incident.py module
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

# Main page layout for the Dash app
app.layout = html.Div([
    dcc.Location(id='url', refresh=False),  # This tracks the current URL
    html.Div(id='page-content'),  # Page content that changes dynamically
    # Embed custom script to listen for messages from iframe
     html.Script('''
        window.addEventListener('message', function(event) {
    if (event.data.type === 'navigate' && event.data.url) {
        console.log("Message received:", event.data.url);  // Ensure this logs the received URL
        window.location.href = event.data.url;  // Trigger navigation in the parent window
    }
});
    ''')
])

# Home layout with dropdown and submit button
home_layout = html.Div(style={'fontFamily': 'Arial, sans-serif', 'margin': '20px'}, children=[
    html.H1(children='Threat Actor Analysis', style={'textAlign': 'center', 'color': '#4B0082'}),
    html.Iframe(
        src='/public/index.html', 
        style={"height": "1000px", "width": "100%"}, 
        sandbox="allow-scripts allow-same-origin allow-forms allow-popups allow-top-navigation-by-user-activation"
    ),

    # Dropdown and submit button
    html.Div(style={'display': 'flex', 'justifyContent': 'space-between', 'alignItems': 'center', 'marginBottom': '20px'}, children=[
        dcc.Dropdown(
            id='group-id-dropdown',
            # Sort the groups alphabetically
            options=[{'label': group, 'value': group} for group in sorted(get_all_groups())],
            placeholder='Select a Group ID',
            style={'min-width': '50%', 'marginRight': '10px'}
        ),
        html.Button('Submit', id='submit-button', n_clicks=0, style={
            'marginLeft': '10px', 'backgroundColor': '#4CAF50', 'color': 'white', 'cursor': 'pointer'
        }),
    ])
])

# Profile layout function for displaying a specific threat actor's page
def profile_layout(actor_name):
    return html.Div(style={'fontFamily': 'Arial, sans-serif', 'margin': '20px'}, children=[
        html.H1(f'Threat Actor Profile: {actor_name}', style={'textAlign': 'center', 'color': '#4B0082'}),
        
        # Display charts and analysis for the selected actor
        html.Div(style={'display': 'flex', 'justifyContent': 'space-between'}, children=[
            dcc.Graph(id='severity-pie-chart'),  # Severity Pie Chart
            dcc.Graph(id='capability-pie-chart'),
            dcc.Graph(id='nist-bar-chart'),# Capability Pie Chart
        ]),
        
           # NIST Violations Bar Chart
        dcc.Graph(id='attack-geo'),
        dcc.Graph(id='incidents'),        # Incidents Scatter Plot
               # Attack Geo Plot
        dcc.Graph(id='cvss-scatter'),      # CVSS Scores Scatter Plot
        dcc.Graph(id='ttp-complexity-bar-chart', figure=go.Figure()) #TTP Complexity Bar Chart
    ])

# Callback to update the URL when the "Submit" button is clicked
@app.callback(
    Output('url', 'pathname'),
    [Input('submit-button', 'n_clicks')],
    [State('group-id-dropdown', 'value')]
)
def redirect_to_profile(n_clicks, selected_group):
    if n_clicks > 0 and selected_group:
        # Normalize the group name by converting to lowercase and replacing spaces with hyphens
        normalized_group = selected_group.lower().replace(' ', '-')
        # Redirect to the profile page with normalized group name
        return f'/profile/{normalized_group}'
    return '/'  # Return home if no selection is made

# Callback to handle page navigation and layout rendering
@app.callback(
    Output('page-content', 'children'),
    [Input('url', 'pathname')]
)
def render_page_content(pathname):
    if pathname == '/':
        return home_layout
    elif pathname.startswith('/profile/'):
        # Normalize the URL path for comparison
        selected_group = pathname.split('/')[-1].replace('-', ' ')
        return profile_layout(selected_group)  # Render the profile layout
    else:
        return html.H1('404 Page Not Found')

# Separate callback to handle chart updates on profile pages
@app.callback(
    [Output('severity-pie-chart', 'figure'),
     Output('capability-pie-chart', 'figure'),
     Output('nist-bar-chart', 'figure'),
     Output('incidents', 'figure'),
     Output('attack-geo', 'figure'),
     Output('cvss-scatter', 'figure'),
     Output('ttp-complexity-bar-chart', 'figure')],
    [Input('url', 'pathname')]
)

#  callback for the update-score-button
@app.callback(
    Output('score-display', 'children'),
    [
        Input('update-score-button', 'n_clicks'),
        Input('score-capability', 'value'),
        Input('score-frequency', 'value'),
        Input('score-industry', 'value'),
        Input('score-violations', 'value')
    ]
)
def update_manual_score(n_clicks, capability, frequency, industry, violations):
    if n_clicks > 0:
        # Perform your score calculation based on inputs here
        score = calculate_score(capability, frequency, industry, violations)
        return f'Score: {score}'
    return 'Score: 0'

def calculate_score(capability, frequency, industry, violations):
    # Dummy score calculation logic, replace with actual logic
    try:
        score = int(capability) + int(frequency) + len(industry) + int(violations)
        return score
    except ValueError:
        return 0


def update_charts(pathname):
    if pathname.startswith('/profile/'):
        # Normalize the URL path to match against the data
        selected_group = pathname.split('/')[-1].replace('-', ' ')

        # Case-insensitive matching for group name
        all_groups = get_all_groups()
        matching_group = next((group for group in all_groups if group.lower() == selected_group.lower()), None)

        if matching_group:
            # Fetch data and create charts
            average_severity, severity_counts, capability_counts = extract_veris_data(get_ttps_of_group(matching_group))
            nist_violations = extract_nist_data(get_ttps_of_group(matching_group))
            cvss_scores = extract_cvss_scores(get_ttps_of_group(matching_group))
            incident_data = get_group_incidents(matching_group)

            severity_fig = create_severity_pie_chart(severity_counts)
            capability_fig = create_capability_pie_chart(capability_counts)
            nist_fig = create_nist_bar_chart(nist_violations)
            incidents_fig = create_incidents_scatter_plot(matching_group, incident_data)
            attack_geo_fig = create_attack_geo_plot(matching_group)
            cvss_scores_fig = create_cvss_scatter_plot(cvss_scores)
            ttp_complexity = create_ttp_complexity_bar_chart(matching_group,get_ttps_of_group(matching_group))

            return [severity_fig, capability_fig, nist_fig, incidents_fig, attack_geo_fig, cvss_scores_fig, ttp_complexity]

    # Return empty figures if no group is selected
    return [go.Figure()] * 6

if __name__ == '__main__':
    app.run_server(debug=True, port=8050)
