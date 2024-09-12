# data_processor.py
import pandas as pd
from mitreattack.stix20 import MitreAttackData

class DataProcessor:
    def __init__(self, mitre_attack_path, nist_path, cve_path, veris_path, cwe_path):
        # Initialize the MitreAttackData object
        self.mitre_attack_data = MitreAttackData(mitre_attack_path)
        
        # Load and preprocess data
        self.nist_df = self._load_and_preprocess_nist(nist_path)
        self.cve_df = self._load_and_preprocess_cve(cve_path)
        self.veris_df = self._load_and_preprocess_veris(veris_path)
        self.cwe_df = self._load_and_preprocess_cwe(cwe_path)
        
        # Get technique data
        self.technique_using_groups = self.mitre_attack_data.get_all_techniques_used_by_all_groups()
        self.groups_dict = self._process_techniques()

    def _load_and_preprocess_nist(self, path):
        df = pd.read_csv(path)
        df = df.drop(df[df['mapping_type']=='non_mappable'].index)
        df = df.drop(columns=['mapping_type','attack_version',
                              'technology_domain','references',
                              'comments','organization',
                              'creation_date','last_update',
                              'mapping_framework_version',
                              'mapping_framework', 'Unnamed: 0'])
        return df

    def _load_and_preprocess_cve(self, path):
        df = pd.read_csv(path)
        df = df.drop(columns=['attack_version','technology_domain',
                              'references','comments',
                              'organization','creation_date',
                              'last_update','mapping_framework_version',
                              'mapping_framework', 'Unnamed: 0'])
        return df

    def _load_and_preprocess_veris(self, path):
        df = pd.read_csv(path)
        df = df.drop(df[df['mapping_type']=='non_mappable'].index)
        df = df.drop(columns=['attack_version','technology_domain',
                              'mapping_type','references',
                              'comments','organization',
                              'creation_date','last_update',
                              'mapping_framework_version',
                              'mapping_framework', 'Unnamed: 0'])
        return df

    def _load_and_preprocess_cwe(self, path):
        df = pd.read_excel(path)
        df.rename(columns={"CVE-ID": "capability_id",
                           "CVSS-V3": "cvss_v3",
                           "CVSS-V2": "cvss_v2",
                           "SEVERITY": "severity",
                           "DESCRIPTION": "description",
                           "CWE-ID": "cwe_id",
                           "ID": "id"}, inplace=True)
        df['severity'] = df['severity'].str.lower()
        return df

    def _process_techniques(self):
        groups_dict = {}
        for id, technique in self.technique_using_groups.items():
            group_id = self.mitre_attack_data.get_attack_id(id)
            ttp_list = [t['object'].external_references[0].external_id for t in technique]
            groups_dict[group_id] = ttp_list
        return groups_dict

    def get_nist_df(self):
        return self.nist_df

    def get_cve_df(self):
        return self.cve_df

    def get_veris_df(self):
        return self.veris_df

    def get_cwe_df(self):
        return self.cwe_df

    def get_groups_dict(self):
        return self.groups_dict
    def analyze_group(self, group_id):
        if group_id not in self.groups_dict:
            print(f"Group ID {group_id} not found.")
            return

        ttps = self.groups_dict[group_id]
        
        # NIST Violations
        nistviolations = self.nist_df.loc[self.nist_df['attack_object_id'].isin(ttps)].reset_index(drop=True)
        nistviolations = nistviolations.drop_duplicates(subset=['capability_id'])
        
        # CVE List
        cve_list = self.cve_df.loc[self.cve_df['attack_object_id'].isin(ttps)].reset_index(drop=True)
        cve_list = cve_list.drop_duplicates(subset=['capability_id'])
        
        # VERIS Data
        veris_df = self.veris_df.loc[self.veris_df['attack_object_id'].isin(ttps)].reset_index(drop=True)
        
        
        cve_severity = pd.merge(cve_list, self.cwe_df, left_on='capability_id', right_on='capability_id', how='inner')
        cve_severity = cve_severity.groupby('severity')['capability_id'].count().reset_index()
        cve_violations = cve_list.groupby('mapping_type')['capability_id'].count().reset_index()
        
        nistviolations = nistviolations.groupby('capability_group')['capability_id'].count().reset_index()
        
        veris_df = veris_df.groupby('capability_group')['capability_id'].count().reset_index()

        return [nistviolations, cve_violations, cve_severity, veris_df]