import json

# Load the MITRE ATT&CK JSON file
with open('data/enterprise-attack.json', 'r') as f:
    attack_data = json.load(f)

mitigations = []
technique_mitigations = {}

# Extract relationships of type 'mitigates' between mitigations and techniques
for obj in attack_data['objects']:
    if obj['type'] == 'relationship' and obj['relationship_type'] == 'mitigates':
        source_ref = obj['source_ref']
        target_ref = obj['target_ref']
        mitigations.append({
            'source_ref': source_ref,
            'target_ref': target_ref
        })

# Count the number of mitigations for each technique (attack-pattern)
for obj in attack_data['objects']:
    if obj['type'] == 'attack-pattern':  # This represents a technique
        technique_id = obj['id']
        technique_mitigations[technique_id] = len([mit for mit in mitigations if mit['target_ref'] == technique_id])

# Variables to track techniques with and without mitigations
techniques_with_mitigations = []
techniques_without_mitigations = []

# Find techniques with and without mitigations and their technique IDs
for obj in attack_data['objects']:
    if obj['type'] == 'attack-pattern':
        # Get the MITRE technique ID from external_references where the source_name is 'mitre-attack'
        technique_id = next((ref['external_id'] for ref in obj.get('external_references', []) if ref['source_name'] == 'mitre-attack'), None)
        if technique_id:
            if technique_mitigations.get(obj['id'], 0) > 0:
                techniques_with_mitigations.append((technique_id, obj['name']))
            else:
                techniques_without_mitigations.append((technique_id, obj['name']))

# Print techniques without mitigations along with their MITRE technique IDs
print(f"\nTechniques without Mitigations ({len(techniques_without_mitigations)}):")
for technique_id, technique_name in techniques_without_mitigations:
    print(f"{technique_id}: {technique_name}")

# Total techniques and techniques with mitigations
total_techniques = len(techniques_with_mitigations) + len(techniques_without_mitigations)
techniques_with_mitigations_count = len(techniques_with_mitigations)

# Calculate the percentage of techniques with mitigations
percentage_with_mitigations = (techniques_with_mitigations_count / total_techniques) * 100

# Print summary statistics
print(f"\nTotal Techniques: {total_techniques}")
print(f"Techniques with Mitigations: {techniques_with_mitigations_count}")
print(f"Percentage of Techniques with Mitigations: {percentage_with_mitigations:.2f}%")
