import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from dash import Dash, dcc, html, Input, Output, State, dash_table
from veris_data import extract_veris_data, load_data as load_vd
from nist_data import extract_nist_data, load_data as load_nd
from cvwe_data import extract_cvss_data, load_data as load_cd
from group_data import get_all_groups, get_ttps_of_group, load_data as load_gd
from incident import load_data as load_incident  # Import load_data from incident.py
from actor_per_country import load_data as load_actor_per_country  # Importing actor_per_country

# cache all the data so the app is fast::
load_nd()  # nist data
load_cd()  # cve data
load_vd()  # veris data
load_gd()  # group data
load_incident()  # incident data
load_actor_per_country()  # Load actor per country data

# Function to load the processed actor per country data from the CSV file
def load_actor_per_country_data():
    return pd.read_csv('actors_per_country.csv')  # Replace with the correct path if needed

# Create the Dash app
app = Dash(__name__, external_stylesheets=['https://codepen.io/chriddyp/pen/bWLwgP.css'])

# Function to load the processed incident data from the CSV file
def load_processed_incident_data():
    return pd.read_csv('incident_list_processed.csv')  # Replace with the correct path if needed

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
            value='',
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
        ]),
    ]),

    html.Div(style={'display': 'flex', 'justifyContent': 'space-between'}, children=[
        html.Div(style={'flex': '1'}, children=[
            dcc.Graph(id='nist-bar-chart'),
        ]),
        html.Div(style={'flex': '1'}, children=[
            dcc.Graph(id='region-bar-chart'),  # New bar chart for regions
        ]),
    ]),

    # New table for CVSS data
    html.Div(id='cvss-table-container', children=[
        dash_table.DataTable(
            id='cvss-data-table',
            style_table={
                'overflowX': 'auto',
                'minWidth': '90%',
                'width': '90%',  # Adjust column widths as needed
                'maxWidth': '90%',
                'border': '1px solid black',
                'padding': '10px',
                'backgroundColor': '#f2f2f2',
                'color': '#333333',
                'fontSize': '14px',
                'fontFamily': 'Arial, sans-serif'
            },
            style_data={
                'whiteSpace': 'normal',  # Enable multiline text within cells
                'textAlign': 'left',
                'backgroundColor': '#f2f2f2',
                'color': '#333333'
            }
        )
    ]),

    # New section for the choropleth map of actors per country
    # html.Div(style={'display': 'flex', 'justifyContent': 'center'}, children=[
    #     dcc.Graph(id='actors-map', style={'height': '800px'})  # Choropleth map
    # ]),

    # New section for the 3D globe of actors per country
    html.Div(style={'display': 'flex', 'justifyContent': 'center'}, children=[
    dcc.Graph(id='actors-map', style={'height': '1500px','width': '2000px'})  # Increased size for 3D globe
])

])

# Callback to update graphs based on TTPs input
@app.callback(
    [Output('severity-pie-chart', 'figure'),
     Output('capability-pie-chart', 'figure'),
     Output('nist-bar-chart', 'figure'),
     Output('cvss-data-table', 'data'),
     Output('region-bar-chart', 'figure'),
     Output('actors-map', 'figure')],  # Add output for the actors map
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
            labels={'capability_id': 'Violations', 'capability_group': 'Type'},
        )

        # Create a bar chart for region-based incidents
        region_fig = px.bar(
            region_counts,
            x='Region',
            y='Count',
            title='Incident Counts by Region',
            labels={'Region': 'Region', 'Count': 'Number of Incidents'},
        )

        # Create the choropleth map for actors per country
        actors_map_fig = px.choropleth(
            actors_per_country,
            locations='country',  # Make sure this matches the column name in your data
            locationmode='country names',  # Ensure countries are mapped by name
            color='number_of_actors',
            hover_name='country',
            color_continuous_scale='Reds',
            title='Distribution of Threat Actors by Country'
        )

        # Create the 3D globe for actors per country, coloring each country based on the number of actors
        actors_map_fig = go.Figure()

        # Create a choropleth trace for the globe
        actors_map_fig.add_trace(
            go.Choropleth(
                locations=actors_per_country['country'],  # Use the country names from the dataset
                locationmode='country names',  # Use country names to match the locations
                z=actors_per_country['number_of_actors'],  # Values to be colored (number of actors)
                colorscale='Plasma',  # High contrast color scale
                marker_line_color='black',  # Country borders color (darker for realism)
                marker_line_width=0.7,  # Thicker borders for better visibility
                hoverinfo='location+z',  # Display country and number of actors on hover
                zmin=0,  # Minimum value for color scale
                zmax=actors_per_country['number_of_actors'].max(),  # Maximum value for color scale
                colorbar=dict(
                    title="Number of Actors",
                    titlefont=dict(color='white'),  # Set the color of the colorbar title to white
                    tickfont=dict(color='white')  # Set the color of the colorbar ticks to white
                )
            )
        )

        # Update layout to display the globe with realistic colors and shading
        actors_map_fig.update_geos(
            projection_type="orthographic",  # Globe projection
            showcoastlines=True,  # Show coastlines
            coastlinecolor="white",  # White coastlines for contrast
            showland=True,
            landcolor="rgb(34, 139, 34)",  # Green land color (realistic)
            showocean=True,
            oceancolor="rgb(0, 105, 148)",  # Deep blue ocean color
            showlakes=True,
            lakecolor="rgb(85, 173, 240)",  # Lighter blue for lakes
            showrivers=False,
            bgcolor="black"  # Black background for space-like appearance
        )

        # Layout configuration for the 3D globe with realistic look
        actors_map_fig.update_layout(
            title=dict(
                text='3D Interactive Globe: Distribution of Threat Actors by Country',
                font=dict(
                size=24,  # Adjust the size of the title if necessary
                color='white'  # Set the title text color to white
            ),
            x=0.5,  # Center the title
        ),
            geo=dict(
                showframe=False,  # Hide the frame around the globe
                showcoastlines=True,  # Show coastlines to highlight land masses
                coastlinecolor="white",  # Make coastlines prominent
                projection_type='orthographic',  # 3D Globe projection
                showland=True,
                landcolor="rgb(34, 139, 34)",  # Realistic land color
                showocean=True,
                oceancolor="rgb(0, 105, 148)",  # Deep blue ocean
                showlakes=True,
                lakecolor="rgb(85, 173, 240)",  # Lakes in lighter blue
                showcountries=True,  # Show country borders
                countrycolor="black",  # Black country borders for contrast
            ),
            height=1000,  # Set the height of the figure
            margin={"r":0,"t":50,"l":0,"b":0},  # Margins
            paper_bgcolor="black",  # Background color to simulate space
            plot_bgcolor="black"  # Plot background color
        )


        # Convert CVSS data into a format suitable for the DataTable
        cvss_data_table = cvss_data.to_dict('records')  # Convert to list of dictionaries

        return severity_fig, capability_fig, nist_fig, cvss_data_table, region_fig, actors_map_fig
    else:
        empty_fig = go.Figure()
        return empty_fig, empty_fig, empty_fig, [], empty_fig, empty_fig


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
