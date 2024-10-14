import pandas as pd
import plotly.graph_objects as go
from pathlib import Path

# Define the base path for the CSV file
base_path = Path(__file__).resolve().parent.parent

# Step 1: Load CSV and Filter Data for the Selected TTPs
def load_complexity_scores(selected_ttps, csv_file_path=base_path / 'data/Updated_Techniques_with_Complexity_Scores_and_Formulas.csv'):
    # Load the CSV file
    try:
        df = pd.read_csv(csv_file_path)
    except FileNotFoundError:
        return pd.DataFrame()  # Return empty DataFrame if file is not found

    # Filter data based on selected TTPs
    filtered_data = df[df['ID'].isin(selected_ttps)]
    return filtered_data if not filtered_data.empty else pd.DataFrame({'ID': selected_ttps, 'New_Complexity_Score': 0})

# Step 2: Create a Heatmap Chart
def create_ttp_heatmap(selected_ttps, filtered_df):
    # Create a DataFrame for all selected TTPs with a default complexity score of 0
    all_ttps_df = pd.DataFrame({'ID': selected_ttps, 'New_Complexity_Score': [0] * len(selected_ttps)})

    # Merge the filtered DataFrame with the all_ttps_df to ensure all TTPs are represented
    heatmap_data = all_ttps_df.merge(filtered_df, on='ID', how='left')

    # Fill NaN values with 0 for missing complexity scores
    heatmap_data['New_Complexity_Score_y'] = heatmap_data['New_Complexity_Score_y'].fillna(0)

    # Create a heatmap using Plotly Graph Objects
    heatmap_fig = go.Figure(data=go.Heatmap(
        z=[heatmap_data['New_Complexity_Score_y']],
        x=heatmap_data['ID'],
        y=['Complexity'],  # Single row, since each TTP has one complexity score
        colorscale='Viridis',
        colorbar=dict(title='Complexity Score')
    ))

    # Update the layout for better readability
    heatmap_fig.update_layout(
        title='TTP Complexity Scores Heatmap',
        xaxis_title='TTP ID',
        yaxis_title='',
        yaxis_showticklabels=False  # Hide the single y-axis label
    )
    
    return heatmap_fig
