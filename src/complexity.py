import pandas as pd
import plotly.graph_objects as go
from pathlib import Path

# Define the base path for the CSV file
base_path = Path(__file__).resolve().parent.parent

# Load CSV and Filter Data for the Selected TTPs
def load_complexity_scores(selected_ttps, csv_file_path=base_path / 'data/techniques_with_complexity_scores.csv'):
    # Load the CSV file
    try:
        df = pd.read_csv(csv_file_path)
    except FileNotFoundError:
        print("CSV file not found. Check the file path.")
        return pd.DataFrame()  # Return empty DataFrame if file is not found

    # Filter data based on selected TTPs
    filtered_data = df[df['ID'].isin(selected_ttps)]
    return filtered_data if not filtered_data.empty else pd.DataFrame({'ID': selected_ttps, 'complexity score': 0})

# Create a Clustered Bar Chart
def create_ttp_complexity_chart(selected_ttps, filtered_df):
    # Create a DataFrame for all selected TTPs with a default complexity score of 0
    all_ttps_df = pd.DataFrame({'ID': selected_ttps, 'complexity score': [0] * len(selected_ttps)})

    # Merge the filtered DataFrame with the all_ttps_df to ensure all TTPs are represented
    chart_data = all_ttps_df.merge(filtered_df, on='ID', how='left')

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

# Example usage
if __name__ == "__main__":
    # Sample selected TTPs for demonstration
    selected_ttps = ['T1548', 'T1548.002', 'T1548.004']  
    filtered_data = load_complexity_scores(selected_ttps)
    
    # If there is any filtered data, create the bar chart
    if not filtered_data.empty:
        bar_fig = create_ttp_complexity_chart(selected_ttps, filtered_data)
        
        # Show the figure if it's created
        if bar_fig:
            bar_fig.show()