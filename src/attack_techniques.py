# heatmap_chart.py
import pandas as pd
import plotly.express as px
from dash import dcc, html

def heatmap_layout():
    return html.Div([
        dcc.Graph(id='heatmap-chart'),
    ])

def create_heatmap_chart():
    # Sample data for heatmap
    data = {
        'actor': ['Actor 1', 'Actor 1', 'Actor 2', 'Actor 2', 'Actor 3', 'Actor 3', 'Actor 1', 'Actor 2', 'Actor 3'],
        'technique': ['Technique A', 'Technique B', 'Technique A', 'Technique C', 'Technique B', 'Technique C', 'Technique C', 'Technique B', 'Technique A'],
        'frequency': [5, 10, 15, 7, 12, 9, 20, 25, 30]  # Sample frequency of techniques used
    }
    df = pd.DataFrame(data)

    # Create a heatmap
    heatmap_fig = px.density_heatmap(
        df,
        x='actor',
        y='technique',
        z='frequency',
        color_continuous_scale='Viridis',
        title='Threat Actor vs. Attack Techniques Heatmap',
        labels={'actor': 'Threat Actor', 'technique': 'Attack Technique', 'frequency': 'Frequency'},
        height=400
    )

    # Update layout for better appearance
    heatmap_fig.update_layout(
        title_font=dict(size=24, color='black'),  # Title font properties
        xaxis_title='Threat Actor',
        yaxis_title='Attack Technique',
        margin=dict(l=40, r=40, t=50, b=40),  # Adjust margins
    )

    return heatmap_fig
