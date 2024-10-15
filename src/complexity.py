import pandas as pd
import plotly.graph_objects as go
from pathlib import Path

# Define the base path for the CSV file
base_path = Path(__file__).resolve().parent.parent


# Create a Clustered Bar Chart
def create_ttp_complexity_chart(selected_ttps, filtered_df):
    # Create a DataFrame for all selected TTPs with a default complexity score of 0
    all_ttps_df = pd.DataFrame({'ID': selected_ttps, 'complexity score': [1] * len(selected_ttps)})

    # Merge the filtered DataFrame with the all_ttps_df to ensure all TTPs are represented
    chart_data = all_ttps_df.merge(filtered_df, on='ID', how='left')
    print(chart_data)

    # Fill NaN values with 0 for missing complexity scores
    chart_data['Complexity_Score_y'] = chart_data['Complexity_Score_y'].fillna(0)

    # Create a clustered bar chart using Plotly Graph Objects
    bar_fig = go.Figure()

    # Add bars for the complexity scores
    bar_fig.add_trace(go.Bar(
        x=chart_data['ID'],
        y=chart_data['Complexity_Score_y'],
        name='Complexity Score',
        marker_color='indigo'
    ))

    # Update the layout for better readability
    bar_fig.update_layout(
        title='TTP Complexity Scores Bar Chart',
        xaxis_title='TTP ID',
        yaxis_title='Complexity Score',
        barmode='group'  # Group bars for clustered effect
    )
    
    return bar_fig
