import plotly.express as px
import pandas as pd

# Sample data for threat actors
data = {
    'actor': ['Actor A', 'Actor B', 'Actor C'],
    'first_seen': ['2020-01-01', '2021-05-15', '2019-08-23'],
    'last_seen': ['2022-01-01', '2022-12-15', '2021-12-23']
}

# Create a DataFrame
df = pd.DataFrame(data)
df['first_seen'] = pd.to_datetime(df['first_seen'])
df['last_seen'] = pd.to_datetime(df['last_seen'])

# Create a timeline chart
fig = px.timeline(df, x_start='first_seen', x_end='last_seen', y='actor', title='Threat Actor Activity Timeline')
fig.show()
