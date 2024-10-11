# geo_distribution.py
import pandas as pd
import plotly.express as px
from dash import dcc, html

def geo_layout():
    return html.Div([
        dcc.Graph(id='geo-distribution-chart'),  # Ensure this ID matches what you're using
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
        template='plotly',
        color='attacks',
        color_continuous_scale=px.colors.sequential.Plasma,
        opacity=0.6,
        labels={'attacks': 'Number of Attacks'},
        hover_data={'latitude': True, 'longitude': True}
    )

    # Update layout for better appearance
    fig.update_layout(
        geo=dict(
            scope='world',
            showland=True,
            landcolor='lightgray',
            subunitcolor='white',
            countrycolor='white',
        ),
        title_font=dict(size=24, color='black'),
        margin=dict(l=0, r=0, t=50, b=0),
    )

    return fig
