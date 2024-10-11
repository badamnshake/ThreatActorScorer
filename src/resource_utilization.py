import pandas as pd
import plotly.express as px
from dash import dcc, html

def resource_utilization_layout():
    return html.Div([
        dcc.Graph(id='resource-utilization-chart'),
    ])

def create_resource_utilization_chart():
    # Sample data for resource utilization
    data = {
        'Resource': ['Time (hours)', 'Tools Used', 'Personnel Involved'],
        'Utilization': [150, 5, 10]  # Sample values
    }
    df = pd.DataFrame(data)

    # Create a bar chart for resource utilization
    fig = px.bar(
        df,
        x='Resource',
        y='Utilization',
        title='Resource Utilization by Threat Actor',
        labels={'Resource': 'Resource Type', 'Utilization': 'Utilization'},
        color='Utilization',
        color_continuous_scale=px.colors.sequential.Viridis,
        text='Utilization'
    )

    fig.update_traces(texttemplate='%{text:.2f}', textposition='outside')
    fig.update_layout(yaxis_title='Utilization', xaxis_title='Resource Type', showlegend=False)

    return fig
