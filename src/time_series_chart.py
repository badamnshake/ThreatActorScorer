import pandas as pd
import plotly.express as px
from dash import dcc, html
from pathlib import Path 

base_path = Path(__file__).resolve().parent.parent

def time_series_layout():
    return html.Div([
        dcc.Graph(id='time-series-chart'),
    ])

def create_time_series_chart(selected_actor=None): 
    # Load the threat actor groups aliases CSV file
    df = pd.read_csv(base_path / 'data/threat_actor_groups_aliases.csv')

    # Prepare a DataFrame to hold the counts of attacks per year
    attacks_count = []

    for _, row in df.iterrows():
        actor_name = row['name'].strip()  # Get the actor name
        years_of_attacks = row['Years of Attacks']  # Get the years of attacks

        if pd.notna(years_of_attacks):  # Ensure there are years recorded
            years = [int(year.strip()) for year in years_of_attacks.split(',')]  # Split and convert to integers

            for year in years:
                attacks_count.append({'actor': actor_name, 'year': year})

    # Create a DataFrame from the attacks_count list
    attacks_count_df = pd.DataFrame(attacks_count)

    # Group by actor and year, and count the number of attacks
    attacks_count_df = attacks_count_df.groupby(['actor', 'year']).size().reset_index(name='attacks')

    # Create a date column for plotting (using the first day of each year)
    attacks_count_df['date'] = pd.to_datetime(attacks_count_df['year'].astype(str) + '-01-01')

    # If a specific actor is selected, filter the DataFrame
    if selected_actor:
        attacks_count_df = attacks_count_df[attacks_count_df['actor'] == selected_actor]
    else:
        return px.line()  # Return an empty figure if no actor is selected

    # Create a time series chart
    fig = px.line(
        attacks_count_df,
        x='date',
        y='attacks',
        color='actor' if not selected_actor else None,
        title='Threat Actor Evolution Over Time' if not selected_actor else f'Evolution Over Time for {selected_actor}',
        labels={'attacks': 'Number of Attacks', 'date': 'Date'},
        markers=True,
        line_shape='linear'
    )

    # Update layout for better appearance
    fig.update_layout(
        title_font=dict(size=24, color='black'),
        xaxis_title='Date',
        yaxis_title='Number of Attacks',
        margin=dict(l=0, r=0, t=50, b=0),
    )

    return fig
