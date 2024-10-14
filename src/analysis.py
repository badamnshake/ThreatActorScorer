# analysis.py

import plotly.express as px
import plotly.graph_objects as go
from dash import dcc, html
from veris_data import extract_veris_data
from nist_data import extract_nist_data
from cvwe_data import extract_cvss_scores
from incident import load_processed_incident_data
#from scorer import get_score_using_datasets, get_score
from group_data import get_group_incidents

# Function to create the layout for the analysis page
def display_analysis_layout(selected_group):
    return html.Div(style={'fontFamily': 'Arial, sans-serif', 'margin': '20px'}, children=[
        html.H1(f'Analysis for {selected_group}', style={'textAlign': 'center'}),

        # Severity and Capability Pie Charts
        html.Div(style={'display': 'flex', 'justifyContent': 'space-between'}, children=[
            dcc.Graph(id='severity-pie-chart', style={'flex': '1', 'marginRight': '10px'}),
            dcc.Graph(id='capability-pie-chart', style={'flex': '1'}),
        ]),

        dcc.Graph(id='incidents'),
        dcc.Graph(id='attack-geo'),
        dcc.Graph(id='cvss-scatter'),
        dcc.Graph(id='nist-bar-chart'),

        # Manual score calculation inputs and button
        html.Div(style={'display': 'flex', 'justifyContent': 'space-between', 'alignItems': 'center', 'marginBottom': '20px'}, children=[
            dcc.Input(id='score-capability', type='text', value='', placeholder='Enter Capability (0-10)', style={'min-width': '20%'}),
            dcc.Input(id='score-frequency', type='text', value='', placeholder='Enter Incident Numbers (0 - n)', style={'min-width': '20%'}),
            dcc.Input(id='score-industry', type='text', value='', placeholder='Enter Industry of Threat Actor', style={'min-width': '20%'}),
            dcc.Input(id='score-violations', type='text', value='', placeholder='Enter NIST Violations', style={'min-width': '20%'}),
            html.Button('Calculate Score Manually', id='update-score-button', n_clicks=0, style={
                'marginLeft': '10px', 'backgroundColor': '#4CAF50', 'color': 'white', 'cursor': 'pointer'
            }),
        ]),

        html.H1(id='score-display', children='Score: 0'),
    ])

# Function to create severity pie chart
def create_severity_pie_chart(severity_counts):
    severity_colors = ['#00FF00', '#FFFF00', '#FFA500', '#FF0000']  # Green, Yellow, Orange, Red
    return px.pie(
        names=severity_counts['severity_level'],
        values=severity_counts['count'],
        title='Distribution of Techniques by Risk Severity',
        color=severity_counts.index,
        color_discrete_sequence=severity_colors
    ).update_layout(
        height=800,  # Increase height
    )

# Function to create capability pie chart
def create_capability_pie_chart(capability_counts):
    return px.pie(
        capability_counts,
        names='capability_group',
        values='capability_id',
        title='Breakdown of Confidentiality, Integrity, and Availability Impact by Threat Actors',
        color_discrete_sequence=['#FF9999', '#66B3FF', '#99FF99']
    )

# Function to create NIST violations bar chart
def create_nist_bar_chart(nist_violations):
    return px.bar(
        nist_violations,
        x='capability_id',
        y='capability_group',
        title='NIST Violations by Type',
        labels={'capability_id': 'Violations', 'capability_group': 'Type'},
    ).update_layout(
        height=800,  # Increase height
        width=1000    # Increase width
    )

# Function to create incidents scatter plot
def create_incidents_scatter_plot(group_id, incident_data):
    gf = get_group_incidents(group_id)
    # Use .loc to safely assign the new 'year' column
    gf.loc[:, 'year'] = gf['event_date'].dt.year

    # Group data by year, industry, and motive, then count the incidents
    incident_counts = gf.groupby(['year', 'industry', 'motive']).size().reset_index(name='incident_count')

    # Create the stacked bar chart
    return px.scatter(
    incident_counts,
    y='industry',  # X-axis is industry
    x='year',  # Y-axis is year
    size='incident_count',  # Bubble size based on number of incidents
    color='motive',  # Color represents motive
    hover_name='industry',  # Hover over to see industry details
    title='Incidents by Year, Motive, and Industry',
    labels={'incident_count': 'Number of Incidents', 'year': 'Year', 'motive': 'Motive'},
    size_max=60,  # Set maximum size for the bubbles
).update_layout(
    yaxis_title='Industry',  # X-axis is Industry
    xaxis_title='Year',  # Y-axis is Year
    legend_title_text='Motive',
    xaxis=dict(range=[2013, 2025]),  # Set fixed time range for y-axis
    width=2500,  # Adjust the width as needed
    height=1000,  # Adjust the height as needed
)



# Function to create geographic plot for attacks
def create_attack_geo_plot(group_id):
    gf = get_group_incidents(group_id)
    
    # Group by country and count the number of incidents
    country_incident_counts = gf.groupby('country').size().reset_index(name='incident_count')

    return px.choropleth(
        country_incident_counts,
        locations='country',
        locationmode='country names',
        hover_name='country',
        color='incident_count',  # Shade countries based on incident count
        title="Global Footprint of Threat Actor's Attacks",
        labels={'incident_count': 'Number of Incidents', 'country': 'Country'},
        color_continuous_scale=px.colors.sequential.Reds,  # Color scale for shading
    ).update_layout(
        width=2500,
        height=800,
        autosize=False,
    )

# Function to create CVSS scores scatter plot
def create_cvss_scatter_plot(cvss_scores):
    return px.scatter(
        cvss_scores,
        x='year',
        y='cvss',
        color='severity',
        #symbol='severity',
        hover_name='cve',
        title='CVEs Exploited',
        labels={'year': 'Year', 'cvss': 'CVSS Score'}
    ).update_layout(
        scattermode="group", scattergap=0.75,
        height=800,
        ).update_traces(
        marker=dict(size=20)  # Set uniform size for all symbols
    ).update_xaxes(
        autorange='reversed'
    )
