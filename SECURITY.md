![CrowdStrike Falcon](https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/cs-logo.png) 

[![CrowdStrike Subreddit](https://img.shields.io/badge/-r%2Fcrowdstrike-white?logo=reddit&labelColor=gray&link=https%3A%2F%2Freddit.com%2Fr%2Fcrowdstrike)](https://reddit.com/r/crowdstrike)

# Security Policy
This document outlines security policy and procedures for the CrowdStrike `MISP-tools` project.

+ [Supported Python versions](#supported-python-versions)
+ [Supported Operating Systems](#supported-operating-systems)
+ [Supported MISP-tools versions](#supported-falconpy-versions)
+ [Reporting a potential security vulnerability](#reporting-a-potential-security-vulnerability)
+ [Disclosure and Mitigation Process](#disclosure-and-mitigation-process)

## Supported Python versions

FalconPy functionality is unit tested to run under the following versions of Python. Unit testing is performed with every pull request or commit to `main`.

| Version | Supported |
| :------- | :--------: |
| 3.12.x  | ![Yes](https://img.shields.io/badge/-YES-green) |
| 3.11.x  | ![Yes](https://img.shields.io/badge/-YES-green) |
| 3.10.x  | ![Yes](https://img.shields.io/badge/-YES-green) |
| 3.9.x   | ![Yes](https://img.shields.io/badge/-YES-green) |
| 3.8.x   | ![Yes](https://img.shields.io/badge/-YES-green) |
| 3.7.x   | ![Yes](https://img.shields.io/badge/-YES-green) |
| 3.6.x   | ![No](https://img.shields.io/badge/-NO-red) |
| <= 3.5  | ![No](https://img.shields.io/badge/-NO-red) |
| <= 2.x.x | ![No](https://img.shields.io/badge/-NO-red) |

## Supported Operating Systems

Unit testing for MISP-tools is performed using Apple macOS and Ubuntu Linux.

## Supported MISP-tools versions

When discovered, we release security vulnerability patches for the most recent release at an accelerated cadence.  

## Reporting a potential security vulnerability

We have multiple avenues to receive security-related vulnerability reports.

Please report suspected security vulnerabilities by:
+ Submitting a [bug](https://github.com/CrowdStrike/MISP-tools/issues).
+ Submitting a [pull request](https://github.com/CrowdStrike/MISP-tools/pulls) to potentially resolve the issue.
+ Sending an email to __oss-security@crowdstrike.com__. 

## Disclosure and mitigation process

Upon receiving a security bug report, the issue will be assigned to one of the project maintainers. This person will coordinate the related fix and release
process, involving the following steps:
+ Communicate with you to confirm we have received the report and provide you with a status update.
    - You should receive this message within 48 - 72 business hours.
+ Confirmation of the issue and a determination of affected versions.
+ An audit of the codebase to find any potentially similar problems.
+ Preparation of patches for all releases still under maintenance.
    - These patches will be submitted as a separate pull request and contain a version update.
    - This pull request will be flagged as a security fix.
    - Once merged, and after post-merge unit testing has been completed, the patch will be immediately published to both PyPI repositories.

<BR/><BR/>

<p align="center"><img src="https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/cs-logo-footer.png"><BR/><img width="300px" src="https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/adversary-goblin-panda.png"></P>
<h3><P align="center">WE STOP BREACHES</P></h3>