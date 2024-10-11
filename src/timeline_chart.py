import plotly.express as px
import pandas as pd

# Load the CSV file from the data folder
csv_file_path = 'data/threat_actor_groups_aliases.csv'
df = pd.read_csv(csv_file_path)

# Convert 'first_seen' and 'last_seen' columns to datetime
df['first_seen'] = pd.to_datetime(df['first_seen'])
df['last_seen'] = pd.to_datetime(df['last_seen'])

# Check for missing or incorrect values in 'name', 'first_seen', 'last_seen'
print(df[['name', 'first_seen', 'last_seen']].head())

# Create a timeline chart using the 'name' column as the y-axis, and 'first_seen', 'last_seen' as the x-axis
fig = px.timeline(df, x_start='first_seen', x_end='last_seen', y='name', title='Threat Actor Activity Timeline')

# Show the chart
fig.show()
