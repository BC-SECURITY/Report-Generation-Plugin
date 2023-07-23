from __future__ import print_function

import json
import os
import tarfile
import urllib.request
from itertools import chain

from stix2 import FileSystemSource, Filter
from stix2.utils import get_type_from_id

import empire.server.common.helpers as helpers


class Attack(object):
    def __init__(self, main_menu):
        self.mainMenu = main_menu
        self.fs = self.load_database()

    def get_commands(self):
        return self.commands

    def register(self, mainMenu):
        pass

    def shutdown(self):
        """If plugin spawns a subprocess or thread provide cleanup here otherwise leave as pass"""
        pass

    def parse_json(self, mitre_json):
        mitre_json = json.loads(mitre_json)
        technique_list = []
        for i in range(len(mitre_json["techniques"])):
            # Finds techniques from group and filters out the sub-techniques
            # TODO:  cannot do subtechniques so split
            technique_list.append(
                mitre_json["techniques"][i]["techniqueID"].split(".")[0]
            )
        disable_module_count = self.disable_modules(technique_list)
        return disable_module_count

    def threat_filtering(self, threat_name):
        # Load MITRE CLI database
        fs = self.load_database()
        alias = self.get_group_by_alias(fs, threat_name)
        techniques = self.get_technique_by_group(fs, alias[0]._inner["id"])
        technique_list = []
        for i in range(len(techniques)):
            # Finds techniques from group and filters out the sub-techniques
            # TODO:  cannot do subtechniques so split
            technique_list.append(
                techniques[i]
                ._inner["external_references"][0]
                ._inner["external_id"]
                .split(".")[0]
            )
        disable_module_count = self.disable_modules(technique_list)
        return disable_module_count

    def attack_searcher(self):
        # Load MITRE CLI database
        fs = self.load_database()
        software = self.get_software_by_alias(fs, "Empire")[0]
        techniques = self.get_techniques_by_software(fs, software)
        return software, techniques

    def all_attacks(self):
        # Load MITRE CLI database
        fs = self.load_database()
        techniques = self.get_all_techniques(fs)
        return techniques

    def get_by_attack_id(self, src, ID):
        tech = src.query([Filter("external_references.external_id", "=", "G0075")])[0]
        return tech

    def get_techniques(self, group_name):
        group = self.get_group_by_alias(self.fs, group_name)[0]
        techniques = self.get_technique_by_group(self.fs, group)
        return techniques

    # mitre defined functions
    def load_database(self):
        try:
            # If database doesn't exist then download it
            database_tar = self.mainMenu.installPath + "/data/cti.tar.gz"
            if not os.path.isfile(
                self.mainMenu.installPath + "/data/cti/enterprise-attack"
            ):
                urllib.request.urlretrieve(
                    "https://github.com/mitre/cti/archive/refs/tags/ATT&CK-v8.2.tar.gz",
                    filename=database_tar,
                )
                if database_tar.endswith("tar.gz"):
                    tar = tarfile.open(database_tar, "r:gz")
                    tar.extractall(path=self.mainMenu.installPath + "/data")
                    tar.close()
            fs = FileSystemSource(
                self.mainMenu.installPath + "/data/cti-ATT-CK-v8.2/enterprise-attack"
            )
            return fs
        except Exception as e:
            print(helpers.color(f"[!] Error: {e}"))

    def get_all_software(self, src):
        filts = [[Filter("type", "=", "malware")], [Filter("type", "=", "tool")]]
        return list(chain.from_iterable(src.query(f) for f in filts))

    def get_all_techniques(self, src):
        filt = [Filter("type", "=", "attack-pattern")]
        return src.query(filt)

    def get_technique_by_name(src, name):
        filt = [Filter("type", "=", "attack-pattern"), Filter("name", "=", name)]
        return src.query(filt)

    def get_techniques_by_content(self, src, content):
        techniques = self.get_all_techniques(src)
        return [
            tech for tech in techniques if content.lower() in tech.description.lower()
        ]

    def get_techniques_since_time(self, src, timestamp):
        filt = [
            Filter("type", "=", "attack-pattern"),
            Filter("created", ">", timestamp),
        ]
        return src.query(filt)

    def get_object_by_attack_id(self, src, typ, attack_id):
        filt = [
            Filter("type", "=", typ),
            Filter("external_references.external_id", "=", attack_id),
        ]
        return src.query(filt)

    def get_group_by_alias(self, src, alias):
        return src.query(
            [Filter("type", "=", "intrusion-set"), Filter("aliases", "=", alias)]
        )

    def get_software_by_alias(self, src, alias):
        return src.query([Filter("type", "=", "tool"), Filter("name", "=", alias)])

    def get_technique_by_group(self, src, stix_id):
        relations = src.relationships(stix_id, "uses", source_only=True)
        return src.query(
            [
                Filter("type", "=", "attack-pattern"),
                Filter("id", "in", [r.target_ref for r in relations]),
            ]
        )

    def get_techniques_by_software(self, src, stix_id):
        relations = src.relationships(stix_id, "uses", source_only=True)
        return src.query(
            [
                Filter("type", "=", "attack-pattern"),
                Filter("id", "in", [r.target_ref for r in relations]),
            ]
        )

    def get_techniques_by_group_software(self, src, group_stix_id):
        # get the malware, tools that the group uses
        group_uses = [
            r
            for r in src.relationships(group_stix_id, "uses", source_only=True)
            if get_type_from_id(r.target_ref) in ["malware", "tool"]
        ]

        # get the technique stix ids that the malware, tools use
        software_uses = src.query(
            [
                Filter("type", "=", "relationship"),
                Filter("relationship_type", "=", "uses"),
                Filter("source_ref", "in", [r.source_ref for r in group_uses]),
            ]
        )

        # get the techniques themselves
        return src.query(
            [
                Filter("type", "=", "attack-pattern"),
                Filter("id", "in", [r.target_ref for r in software_uses]),
            ]
        )

    def get_technique_users(self, src, tech_stix_id):
        groups = [
            r.source_ref
            for r in src.relationships(tech_stix_id, "uses", target_only=True)
            if get_type_from_id(r.source_ref) == "intrusion-set"
        ]

        software = [
            r.source_ref
            for r in src.relationships(tech_stix_id, "uses", target_only=True)
            if get_type_from_id(r.source_ref) in ["tool", "malware"]
        ]

        return src.query(
            [
                Filter("type", "in", ["intrusion-set", "malware", "tool"]),
                Filter("id", "in", groups + software),
            ]
        )

    def get_techniques_by_platform(self, src, platform):
        return src.query(
            [
                Filter("type", "=", "attack-pattern"),
                Filter("x_mitre_platforms", "=", platform),
            ]
        )

    def get_tactic_techniques(self, src, tactic):
        techs = src.query(
            [
                Filter("type", "=", "attack-pattern"),
                Filter("kill_chain_phases.phase_name", "=", tactic),
            ]
        )

        # double checking the kill chain is MITRE ATT&CK
        return [
            t
            for t in techs
            if {
                "kill_chain_name": "mitre-attack",
                "phase_name": tactic,
            }
            in t.kill_chain_phases
        ]

    def get_mitigations_by_technique(self, src, tech_stix_id):
        relations = src.relationships(tech_stix_id, "mitigates", target_only=True)
        return src.query(
            [
                Filter("type", "=", "course-of-action"),
                Filter("id", "in", [r.source_ref for r in relations]),
            ]
        )

    def getTacticsByMatrix(self, src):
        tactics = {}
        matrix = src.query(
            [
                Filter("type", "=", "x-mitre-matrix"),
            ]
        )

        for i in range(len(matrix)):
            tactics[matrix[i]["name"]] = []
            for tactic_id in matrix[i]["tactic_refs"]:
                tactics[matrix[i]["name"]].append(
                    src.query([Filter("id", "=", tactic_id)])[0]
                )

        return tactics

    def getRevokedBy(self, stix_id, src):
        relations = src.relationships(stix_id, "revoked-by", source_only=True)
        revoked_by = src.query(
            [
                Filter("id", "in", [r.target_ref for r in relations]),
                Filter("revoked", "=", False),
            ]
        )
        if revoked_by is not None:
            revoked_by = revoked_by[0]

        return revoked_by

    def shutdown(self):
        pass
