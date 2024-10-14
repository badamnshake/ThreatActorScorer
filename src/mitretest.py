import mitreattack.attackToExcel.attackToExcel as attackToExcel
import mitreattack.attackToExcel.stixToDf as stixToDf

# Download and parse ATT&CK STIX data
attackdata = attackToExcel.get_stix_data("enterprise-attack")

# Parse and retrieve threat actor groups
groups_df = stixToDf.groupsToDf(attackdata)

# Display all threat actors
print(groups_df)

# Filter for a specific threat actor
specific_actor_name = "APT28"  # Replace with the name of the actor you're interested in
specific_actor_df = groups_df[groups_df["name"].str.contains(specific_actor_name, case=False)]

# Display information about the specific threat actor
print(specific_actor_df)
