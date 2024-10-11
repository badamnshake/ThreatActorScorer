# time_series_chart.py
import pandas as pd
import plotly.express as px
from dash import dcc, html

def time_series_layout():
    return html.Div([
        dcc.Graph(id='time-series-chart'),
    ])

def create_time_series_chart():
    # Sample data for time series
    data = {
        'date': pd.date_range(start='2022-01-01', periods=12, freq='M'),  # Monthly data for one year
        'attacks': [5, 10, 15, 7, 12, 9, 20, 25, 30, 18, 22, 35],  # Sample number of attacks
        'actor': ['Actor 1'] * 12  # All attacks attributed to 'Actor 1'
    }
    df = pd.DataFrame(data)

    # Create a time series chart
    fig = px.line(
        df,
        x='date',
        y='attacks',
        title='Threat Actor Evolution Over Time',
        labels={'attacks': 'Number of Attacks', 'date': 'Date'},
        markers=True,  # Add markers to the line
        line_shape='linear'  # Change line shape
    )

    # Update layout for better appearance
    fig.update_layout(
        title_font=dict(size=24, color='black'),  # Title font properties
        xaxis_title='Date',
        yaxis_title='Number of Attacks',
        margin=dict(l=0, r=0, t=50, b=0),  # Adjust margins
    )

    return fig
