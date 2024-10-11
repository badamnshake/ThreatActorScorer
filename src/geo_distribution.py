# geo_distribution.py
import pandas as pd
import plotly.express as px
from dash import dcc, html

# Load the CSV file

csv_file_path = r'..\data\actors_per_country_filled_lat_lon.csv'
df = pd.read_csv(csv_file_path)


# Initialize a dictionary to hold actor-country relationships with lat/long
actor_country_map = {}

# Iterate over each row in the DataFrame
for index, row in df.iterrows():
    country = row['country']
    latitude = row['latitude']
    longitude = row['longitude']
    actors = row['actor_list'].split(', ')
    
    # Map each actor to the corresponding country, latitude, and longitude
    for actor in actors:
        actor = actor.strip()  # Remove any leading/trailing spaces
        if actor not in actor_country_map:
            actor_country_map[actor] = []
        actor_country_map[actor].append({
            'country': country,
            'latitude': latitude,
            'longitude': longitude
        })

def geo_layout():
    return html.Div([
        dcc.Graph(id='geo-distribution-chart'),  # Ensure this ID matches what you're using
    ])

def create_geo_distribution_chart(selected_actor):
    if selected_actor not in actor_country_map:
        return px.scatter_geo()  # Return an empty figure if the actor is not found
    
    # Prepare the data for the selected actor
    locations = actor_country_map[selected_actor]
    df = pd.DataFrame(locations)

    # Create a geographical distribution chart
    fig = px.scatter_geo(
        df,
        lat='latitude',
        lon='longitude',
        size=[1]*len(df),  # Static size, or adjust based on some value if needed
        hover_name='country',  # Show country name on hover
        title=f'Geographical Distribution of Attacks by {selected_actor}',
        projection='natural earth',
        template='plotly',
        color='country',  # Optional: color by country
        opacity=0.6,
        labels={'country': 'Country'},
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
