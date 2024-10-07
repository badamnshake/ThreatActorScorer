import pandas as pd
import re
from pathlib import Path

base_path = Path(__file__).resolve().parent.parent

# Initialize a variable to cache the loaded data
cached_data = None

def load_data():
    """Load the Incident Data and cache it for reuse."""
    
    global cached_data
    if cached_data is None:
        cached_data = load_count_data()  # Cache the processed data for future calls

# Function to process incident data, accepting the path as an argument
def load_count_data():
    """Load the Data from CSV file."""
    actor_per_country_df = pd.read_csv(base_path / 'data/cyber_events.csv') #Dynamic Path

    #Group data by 'actor' and 'country' columns
    actor_country_counts = actor_per_country_df.groupby(['country', 'actor']).size().reset_index(name='actor_count')

    #Group by country to get no. of actors in each country
    actors_per_country = actor_country_counts.groupby('country')['actor'].nunique().reset_index(name='number_of_actors')

    #Save Results in separate CSV
    actors_per_country.to_csv('actors_per_country.csv', index=False)
