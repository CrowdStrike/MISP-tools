import os
from numbers import Number
from pymisp import MISPTag
from .adversary import Adversary
from .confidence import MaliciousConfidence
from .kill_chain import KillChain
from .helper import confirm_boolean_param

def __update_tag_list(tagging_list:list, tag_value: str):
    _tag = MISPTag()
    _tag.from_dict(name=tag_value)
    tagging_list.append(_tag)

    return tagging_list


def __log_galaxy_miss(family: str, galaxy_list: list, galaxy_file: str):
    if galaxy_list is None:
        if os.path.exists(galaxy_file):
            with open(galaxy_file, "r", encoding="utf-8") as miss_file:
                missing = miss_file.read()
            missing = missing.split("\n")
            if "" in missing:
                missing.remove("")
        else:
            missing = []
        galaxy_list = missing
    if family not in galaxy_list:
        galaxy_list.append(family)

    return galaxy_list

def tag_attribute_malicious_confidence(ind, tags):
    malicious_confidence = ind.get('malicious_confidence')
    if malicious_confidence:
        if not isinstance(MaliciousConfidence[malicious_confidence.upper()], Number):
            tags = __update_tag_list(tags,
                f"CrowdStrike:indicator:malicious-confidence: {malicious_confidence.upper()}"
                )
    return tags

def tag_attribute_actor(ind, tags):
    returned = False
    for actor in ind.get('actors', []):
        for adv in [a for a in dir(Adversary) if "__" not in a]:
            if adv in actor and " " not in actor:
                actor = actor.replace(adv, f" {adv}")
                branch = actor.split(" ")[1]
                #event.add_attribute_tag(f"CrowdStrike:adversary:branch: {branch}", indicator_object.uuid)
                tags = __update_tag_list(tags, f"CrowdStrike:indicator:adversary:branch: {branch}")
                tags = __update_tag_list(tags, f'CrowdStrike:adversary="{actor.title()}"')
                returned = True

    return returned, tags


def tag_attribute_targets(ind, tags):
    for target in ind.get('targets', []):
        tags = __update_tag_list(tags, f"CrowdStrike:target:sector: {target}")

    return tags


def tag_attribute_threats(ind, tags):
    returned = False
    for threat_type in ind.get("threat_types"):
        tags = __update_tag_list(tags, f"CrowdStrike:indicator:threat: {threat_type.upper()}")
        returned = True

    return returned, tags


def tag_attribute_family(ind, tags, import_set, settings, missed, mfile):
    family_found = False
    for malware_family in ind.get('malware_families', []):
        galaxy = import_set["galaxy_map"].get(malware_family)
        if galaxy is not None:
            tags = __update_tag_list(tags, galaxy)
            family_found = True

        if not family_found:
            __log_galaxy_miss(malware_family, missed, mfile)
        #     if confirm_boolean_param(settings["TAGGING"].get("taxonomic_WORKFLOW", False)):
        #         tags = __update_tag_list(tags, 'workflow:todo="add-missing-misp-galaxy-cluster-values"')
        #     else:
        #         tags = __update_tag_list(tags, import_set["unknown_mapping"])

    return tags, missed


def tag_attribute_labels(ind, tags, log_util, b_branch, b_threat, settings):
    labels = [lab.get("name") for lab in ind.get("labels")]
    for label in labels:
        label = label.lower()
        parts = label.split("/")
        label_val = parts[1]
        label_type = parts[0].lower().replace("killchain", "kill-chain").replace("threattype", "threat")
        label_type = label_type.replace("maliciousconfidence", "malicious-confidence").replace("mitreattck", "mitre-attck")
        if label_type == "actor" and not b_branch:
            for adv in [a for a in dir(Adversary) if "__" not in a]:
                if adv in label_val:
                    #event.add_attribute_tag(f"CrowdStrike:adversary:branch: {adv}", indicator_object.uuid)
                    log_util.debug(f"Tagged adversary {adv}")
                    tags = __update_tag_list(tags, f"CrowdStrike:indicator:adversary: {adv}")

        if label_type == "threat" and not b_threat:
            scnt = 0
            for s in label_val:
                scnt += 1
                if s.isupper() and scnt > 1:
                    label_val = label_val.replace(s, f" {s}")
            #target_event.add_attribute_tag(f"CrowdStrike:indicator:threat: {label_val.upper()}", uuid)
            tags = __update_tag_list(tags, f"CrowdStrike:indicator:threat: {label_val.upper()}")
            log_util.debug(f"Tagged threat {label_val.upper()} to event")
        
        if label_type == "kill-chain":
            for kc in list(k for k in dir(KillChain) if "__" not in k):
                if kc == label_val.upper():
                    log_util.debug("Tagging taxonomic kill chain match: kill-chain:%s", KillChain[kc].value)
                    if confirm_boolean_param(settings["TAGGING"].get("taxonomic_KILL-CHAIN", False)):
                        #event.add_tag(f"kill-chain:{KillChain[kc].value}")
                        #target_event.add_attribute_tag(f"kill-chain:{KillChain[kc].value}", uuid)
                        tags = __update_tag_list(tags, f"kill-chain:{KillChain[kc].value}")
                        log_util.debug(f"Tagged kill chain {KillChain[kc].value}")
        if label_type in ["malicious-confidence", "kill-chain", "threat", "malware", "mitre-attck", "actor"]:
            label_val = label_val.upper()
        # if label_type == "actor":
        #     label_type = "adversary"
        #     for act in [a for a in dir(Adversary) if "__" not in a]:
        #         if act in label_val:
        #             label_val = label_val.replace(act, f" {act}")
                    # Makes deep searches difficult after there's a lot of data
                    #tag_list = __update_tag_list(tag_list, f"CrowdStrike:adversary: {label_val}")
        
        if label_type not in ["kill-chain", "actor"]:
            tags = __update_tag_list(tags, f"CrowdStrike:indicator:{label_type}: {label_val}")
            log_util.debug(f"Tagged {label_type} {label_val}")

    return tags
