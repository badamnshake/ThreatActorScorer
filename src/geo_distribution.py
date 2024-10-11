# geo_chart.py
import pandas as pd
import plotly.express as px
from dash import dcc, html

def geo_layout():
    return html.Div([
        dcc.Graph(id='geo-distribution-chart'),
    ])

def create_geo_distribution_chart():
    # Static data for testing
    data = {
        'latitude': [34.0522, 40.7128, 37.7749],
        'longitude': [-118.2437, -74.0060, -122.4194],
        'attacks': [10, 20, 15],
        'actor': ['Actor 1', 'Actor 1', 'Actor 1']
    }
    df = pd.DataFrame(data)

    # Create a geographical distribution chart with enhancements
    fig = px.scatter_geo(
        df,
        lat='latitude',
        lon='longitude',
        size='attacks',
        hover_name='actor',
        size_max=30,
        title='Geographical Distribution of Attacks by Actor 1',
        projection='natural earth',
        template='plotly',  # Use a predefined template
        color='attacks',  # Color by the number of attacks
        color_continuous_scale=px.colors.sequential.Plasma,  # Change the color scale
        opacity=0.6,  # Add some transparency
        labels={'attacks': 'Number of Attacks'},  # Label for hover text
        hover_data={'latitude': True, 'longitude': True}  # Show latitude and longitude on hover
    )

    # Update layout for better appearance
    fig.update_layout(
        geo=dict(
            scope='world',  # Show the entire world or specify a continent
            showland=True,  # Show land
            landcolor='lightgray',  # Land color
            subunitcolor='white',  # Color of country borders
            countrycolor='white',  # Color of countries
        ),
        title_font=dict(size=24, color='black'),  # Title font properties
        margin=dict(l=0, r=0, t=50, b=0),  # Adjust margins
    )

    return fig

