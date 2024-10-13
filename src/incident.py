import pandas as pd
# import re
# import pycountry
import pycountry_convert as pc
from pathlib import Path 

base_path = Path(__file__).resolve().parent.parent

# Initialize a variable to cache the loaded data
cached_data = None

# Function to load the processed incident data from the CSV file
def load_processed_incident_data():
    return pd.read_csv( base_path / 'data/incident_list_processed.csv')

# Function to load the processed actor per country data from the CSV file
def load_actor_per_country_data():
    # Ensure that the file path is correct and relative to your setup
    return pd.read_csv(base_path /  'data/actors_per_country_filled_lat_lon.csv')

'''
def load_data():
    """Load the Incident Data and cache it for reuse."""
    
    global cached_data
    if cached_data is None:
        cached_data = load_incident_data()  # Cache the processed data for future calls

# Function to process incident data, accepting the path as an argument
def load_incident_data():
    """Load the Incident data from CSV files."""
    incident_df = pd.read_csv(base_path / 'data/cyber_operations_incidents.csv')  # Now using the dynamic file path from main.py

    # Define the columns to check
    columns_to_check = ['Title', 'Victims']  # Replace with your actual column names

    # Define region terms mapping
    region_terms = {
        'asia': 'Asia',
        'asian': 'Asia',
        'europe': 'Europe',
        'european': 'Europe',
        'americas': 'Americas',
        'america': 'Americas',
        'american': 'Americas',
        'north america': 'Americas',
        'south america': 'Americas',
        'oceania': 'Oceania',
        'africa': 'Africa',
        'african': 'Africa',
        'antarctica': 'Antarctica',
    }

    # Automatically generate country terms including demonyms from pycountry
    country_terms = {}
    for country in pycountry.countries:
        country_name = country.name.lower()
        country_alpha2 = country.alpha_2
        country_terms[country_name] = country.name

        # Add common country code variations
        if hasattr(country, 'official_name'):
            official_name = country.official_name.lower()
            country_terms[official_name] = country.name

        # Get demonyms (nationalities)
        if hasattr(country, 'demonym'):
            demonym = country.demonym.lower()
            country_terms[demonym] = country.name

    # Manually add adjectival forms (adjectives), demonyms, and country aliases not included by pycountry
    additional_country_terms = {
        'russian': 'Russia',
        'south korean': 'South Korea',
        'south korea': 'South Korea',
        'north korean': 'North Korea',
        'north korea': 'North Korea',
        'ukrainian': 'Ukraine',
        'british': 'United Kingdom',
        'american': 'United States',
        'taiwanese': 'Taiwan',
        'canadian': 'Canada',
        'german': 'Germany',
        'french': 'France',
        'italian': 'Italy',
        'japanese': 'Japan',
        'spanish': 'Spain',
        'indian': 'India',
        'chinese': 'China',
        'australian': 'Australia',
        'mexican': 'Mexico',
        'brazilian': 'Brazil',
        'saudi': 'Saudi Arabia',
        'south african': 'South Africa',
        'pakistani': 'Pakistan',
        'turkish': 'Turkey',
        'swiss': 'Switzerland',
        'greek': 'Greece',
        'swedish': 'Sweden',
        'norwegian': 'Norway',
        'dutch': 'Netherlands',
        'belgian': 'Belgium',
        'argentinian': 'Argentina',
        'colombian': 'Colombia',
        'venezuelan': 'Venezuela',
        'chilean': 'Chile',
        'peruvian': 'Peru',
        'danish': 'Denmark',
        'finnish': 'Finland',
        'icelandic': 'Iceland',
        'portuguese': 'Portugal',
        'polish': 'Poland',
        'hungarian': 'Hungary',
        'egyptian': 'Egypt',
        'nigerian': 'Nigeria',
        'kenyan': 'Kenya',
        'ethiopian': 'Ethiopia',
        'sudanese': 'Sudan',
        'israeli': 'Israel',
        'palestinian': 'Palestine',
        'lebanese': 'Lebanon',
        'iranian': 'Iran',
        'iraqi': 'Iraq',
        'syrian': 'Syria',
        'yemeni': 'Yemen',
        'jordanian': 'Jordan',
        'kuwaiti': 'Kuwait',
        'qatari': 'Qatar',
        'emirati': 'United Arab Emirates',
        'omanian': 'Oman',
        'indonesian': 'Indonesia',
        'malaysian': 'Malaysia',
        'singaporean': 'Singapore',
        'filipino': 'Philippines',
        'vietnamese': 'Vietnam',
        'cambodian': 'Cambodia',
        'thai': 'Thailand',
        'south sudanese': 'South Sudan',
        'syrian': 'Syria',
        'libyan': 'Libya',
        'moroccan': 'Morocco',
        'tunisian': 'Tunisia',
        'algerian': 'Algeria',
        'iraqi': 'Iraq',
        # Continue expanding for as many countries and adjectivals as needed
    }
    country_terms.update(additional_country_terms)

    # Combine country and region terms
    all_terms = {**country_terms, **region_terms}

    # Create a regex pattern to match any of the terms
    pattern = re.compile(
        r'\b(' + '|'.join(re.escape(term) for term in all_terms.keys()) + r')\b', re.IGNORECASE
    )

    # Function to get the region for a country
    def get_region_for_country(country_name):
        try:
            country = pycountry.countries.get(name=country_name)
            if not country:
                # Try fuzzy search
                country = pycountry.countries.search_fuzzy(country_name)[0]
            country_code = country.alpha_2
            continent_code = pc.country_alpha2_to_continent_code(country_code)
            continent_name = pc.convert_continent_code_to_continent_name(continent_code)
            continent_to_region = {
                'Europe': 'Europe',
                'Asia': 'Asia',
                'North America': 'Americas',
                'South America': 'Americas',
                'Africa': 'Africa',
                'Oceania': 'Oceania',
                'Antarctica': 'Antarctica',
            }
            return continent_to_region.get(continent_name, 'Unknown')
        except Exception as e:
            print(f"Could not get region for country '{country_name}': {e}")
            return 'Unknown'

    # Function to process each row
    def process_row(row):
        text = ' '.join(str(row[col]) for col in columns_to_check if pd.notnull(row[col]))
        text = text.lower()
        matches = pattern.findall(text)
        matched_countries = set()
        matched_regions = set()
        for match in matches:
            standard_term = all_terms[match.lower()]
            if standard_term in region_terms.values():
                matched_regions.add(standard_term)
            elif standard_term in country_terms.values():
                matched_countries.add(standard_term)
        # Apply conditions to determine output
        if len(matched_countries) == 1 and len(matched_regions) == 0:
            return matched_countries.pop()
        elif len(matched_countries) >= 2:
            regions = set()
            for country in matched_countries:
                region = get_region_for_country(country)
                if region != 'Unknown':
                    regions.add(region)
            if len(regions) == 1:
                return regions.pop()
            elif len(regions) > 1:
                return 'global'
            else:
                return 'global'
        elif len(matched_regions) == 1 and len(matched_countries) == 0:
            return matched_regions.pop()
        elif len(matched_regions) >= 2:
            return 'global'
        else:
            return 'Unknown'

    # Apply the function to each row
    incident_df['Output'] = incident_df.apply(process_row, axis=1)

    # Save the updated DataFrame
    # incident_df.to_csv('incident_list_processed.csv', index=False)

'''