import pandas as pd
from pathlib import Path 

base_path = Path(__file__).resolve().parent.parent

# Initialize a variable to cache the loaded data
cached_data = None


def load_data():
    """Load the VERIS data and cache it for reuse."""
    
    global cached_data
    if cached_data is None:
        cached_data = load_nist_data()  # Cache the processed data for future calls

def load_nist_data():
    # nist data preprocessing and cleaning
    # this data maps nist violations against mitre techniques
    # nist mapping
    nist_df = pd.read_csv( base_path / 'data/nist_800_53_mapping.csv')
    nist_df = nist_df.drop(nist_df[nist_df['mapping_type']=='non_mappable'].index)
    nist_df = nist_df.drop(columns=['mapping_type','attack_version',
                                    # 'technology_domain',
                                    'references',
                                    'comments',
                                    'organization',
                                    'creation_date',
                                    'last_update',
                                    'mapping_framework_version',
                                    'mapping_framework', 'Unnamed: 0'])
    return nist_df



def extract_nist_data(ttps):

    global cached_data
    if cached_data is None:
        cached_data = load_nist_data()

    # get all nist violations by one technique(ttp)
    nistviolations = cached_data.loc[cached_data['attack_object_id'].isin(ttps)].reset_index(drop=True)

    # filter duplicates (ex. t1001 & 1002 both has access control violations AC02, but that is only one record)
    nistviolations = nistviolations.drop_duplicates(subset=['capability_id'])
    nistviolations = nistviolations.groupby('capability_group')['capability_id'].count().reset_index()

    return nistviolations