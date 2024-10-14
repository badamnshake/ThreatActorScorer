import pandas as pd
import plotly.express as px
from pathlib import Path

base_path = Path(__file__).resolve().parent.parent

def create_first_last_seen_chart(selected_actor=None):
    # Load the threat actor data
    df = pd.read_csv(base_path / 'data/threat_actor_groups_aliases.csv')
    
    # If no actor is selected, return an empty figure
    if not selected_actor:
        return px.scatter()  # Use scatter for an empty figure or another appropriate chart

    # Filter the DataFrame for the selected actor
    df = df[df['name'] == selected_actor]

    # Check if any data is available for the selected actor
    if df.empty:
        return px.scatter()  # Return an empty figure if no data is available for the selected actor

    # Convert 'first_seen' and 'last_seen' to datetime format
    df['first_seen'] = pd.to_datetime(df['first_seen'])
    df['last_seen'] = pd.to_datetime(df['last_seen'])

    # Create a new DataFrame for timeline plotting
    timeline_data = df[['name', 'first_seen', 'last_seen']].copy()

    # Create a timeline chart
    fig = px.timeline(
        timeline_data,
        x_start='first_seen',
        x_end='last_seen',
        y='name',
        title=f'Timeframe of Attacks for {selected_actor}',
        labels={'first_seen': 'First Seen', 'last_seen': 'Last Seen'},
    )

    # Update layout for better appearance
    fig.update_layout(
        title_font=dict(size=24, color='black'),
        xaxis_title='Date',
        yaxis_title='Threat Actor',
        margin=dict(l=0, r=0, t=50, b=0),
    )

    return fig
