![CrowdStrike Falcon](https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/cs-logo.png) 

[![Twitter URL](https://img.shields.io/twitter/url?label=Follow%20%40CrowdStrike&style=social&url=https%3A%2F%2Ftwitter.com%2FCrowdStrike)](https://twitter.com/CrowdStrike)

# MISP Tools
This repository is focused on solutions for integrating CrowdStrike with the [MISP project](https://github.com/MISP/MISP).

- [Manual Import](#manual-import) - Manually import Actors, Indicators or Reports from CrowdStrike Falcon X into your MISP instance.
- [MISP Modules](#modules) - MISP modules that leverage CrowdStrike.


## Manual import
This solution will import actors, indicators or reports from CrowdStrike Falcon X into your MISP instance from a specified number of days backwards in time.

![MISP Import](docs/misp-import.gif)

This solution supports standalone execution as well as container deployment.

- [Configuration](#configuration)
- [Container deployment](#running-the-solution-as-a-container)
- [Standalone execution](#standalone-execution)

### Configuration

#### Requirements
This application requires Python **3.6+**.

The following Python packages must be installed in order for this application to function.

- [`crowdstrike-falconpy`](https://github.com/CrowdStrike/falconpy) (v0.9.0+)
- [`pymisp`](https://github.com/MISP/MISP)

#### CrowdStrike API credential Scope
Your API credentials will need **READ** access to:

- Actors (Falcon X)
- Indicators (Falcon X)
- Reports (Falcon X)

#### MISP server requirements
You will need to generate an authorization key (and potentially a user) to use for access to the MISP instance. You will also need to create an organization called "CrowdStrike", and provide the UUID for this organization in the configuration file as detailed below.

#### misp_import.ini
The are two sections within the `misp_import.ini` configuration file, [`CrowdStrike`](#crowdstrike) and [`MISP`](#misp-1).

##### CrowdStrike
The CrowdStrike section contains configuration detail for communicating with your CrowdStrike tenant.

| | |
| :-- | :-- |
| `client_id` | Your CrowdStrike API client identifier. |
| `client_secret` | Your CrowdStrike API client secret. |
| `crowdstrike_url` | The base URL to use for requests to CrowdStrike. You may pass the full URL, the URL string, or just the shortname (US1, US2, EU1, USGOV1). |
| `api_request_max` | Limit to use for requests to the CrowdStrike API. The US-1 CrowdStrike region supports 5000 for a limit.  Other regions support 2500. |
| `api_enable_ssl` | Boolean to specify if SSL verification should be disabled. | 
| `reports_timestamp_filename` | Filename to use to store the timestamp for the last imported report. |
| `indicators_timestamp_filename` | Filename to use to store the timestamp for the last imported indicator. |
| `actors_timestamp_filename` | Filename to use to store the timestamp for the last imported actor. |
| `init_reports_days_before` | Maximum age of reports to import. |
| `init_indicators_days_before` | Maximum age of indicators to import. |
| `init_actors_days_before` | Maximum age of actors to import. |
| `reports_unique_tag` | Originating from CrowdStrike unique report tag. |
| `indicators_unique_tag` | Originating from CrowdStrike unique indicator tag. |
| `actors_unique_tag` | Originating from CrowdStrike unique actor tag. |
| `reports_tags` | Tags to apply to imported reports. |
| `indicators_tags` | Tags to apply to imported indicators. |
| `actors_tags` | Tags to apply to imported actors. |
| `unknown_mapping` | Name to use for tag used to flag unknown malware families. |

##### MISP
The MISP section contains detail for communicating with your MISP instance.

| | |
| :-- | :-- |
| `misp_url` | URL to use for the MISP instance. |
| `misp_auth_key` | MISP authorization key used to import data. |
| `crowdstrike_org_uuid` | The UUID of the CrowdStrike organization within your MISP instance. This is used as the organization for all imports. |
| `misp_enable_ssl` | Boolean to specify if SSL should be used to communicate with the MISP instance. |
| `max_threads` | Number of processor threads to use for processing. |
| `miss_track_file` | The name of the file used to track malware families without a galaxy mapping.
| `galaxies_map_file` | The name of the galaxy mapping file (default: `galaxy.ini`) |

#### galaxy.ini
The galaxy mapping file, `galaxy.ini` contains one section, `Galaxy`. This section contains galaxy mappings for indicator malware families.

These mappings use the following format:

MalwareFamily = Misp_Galaxy_Mapping

**Example**
```ini
njRAT = misp-galaxy:malpedia="NjRAT"
```

> More malware family detail and additional mappings for unidentified malware families can be found at https://www.misp-project.org/galaxy.html.

#### Command line arguments
This solution accepts the following command line arguments.

| Argument | Purpose |
| :--- | :--- |
| `-h` or `--help` | Show command line help and exit. |
| `--clean_reports` | Remove all CrowdStrike tagged reports from the MISP instance. |
| `--clean_indicators` | Remove all CrowdStrike tagged indicators from the MISP instance. |
| `--clean_actors` | Remove all CrowdStrike tagged actors from the MISP instance. |
| `--debug` | Enable debug output. |
| `--max_age` | Maximum age (in days) of actors, indicators or reports to import. |
| `--related_indicators` | Import indicators related to reports. |
| `--all_indicators` | Import all indicators. |
| `--delete_outdated_indicators` | Checks as indicators are imported to see if they are flagged for deletion, if so they are removed instead of imported. |
| `--reports` | Import reports. |
| `--actors` | Import actors. |
| `--config` | Path to the local configuration file, defaults to `misp_import.ini`. |
| `--no_dupe_check` | Disable duplicate checking on indicator import. |


### Running the solution as a container
This solution can also be run as a container using the provided Docker file.

#### Building the container
To build the container, execute the following command. Depending upon permissions within your environment, you may need to execute this with escalated permissions.

```
docker build . -t misp
```

#### Running the container
Once your container has been built, you can start one up using the following (you may also need to escalate permissions here):

> This example only shows the help dialog and exits.

```shell
docker run -it --rm \
    -v $(pwd)/misp_import.init:/misp/misp_import.init \
    misp --help
```

> This example demonstrates cleaning all indicators from your MISP instance.

```shell
docker run -it --rm \
    -v $(pwd)/misp_import.init:/misp/misp_import.init \
    misp --clean_indicators
```



### Running the solution manually
This solution can be run manually as long as all Python requirements have been met and the configuration files have been updated to reflect your environment.

#### Examples
The following examples demonstrate different variations of executing the solution locally.


**Import all data (actors, indicators and reports)**
```python
python3 misp_import.py --actors --all_indicators --reports
```

**Delete just indicators**
```python
python3 misp_import.py --clean_indicators
```

**Only import reports and related indicators**
```python
python3 misp_import.py --related_indicators --reports
```


## Modules
The MISP project supports autonomous modules that can be used to extend overall functionality. These modules are broken out into three categories; _expansion_, _import_ and _export_.

The following MISP modules currently leverage CrowdStrike:

- [CrowdStrike Falcon expansion module](https://github.com/MISP/misp-modules/blob/main/misp_modules/modules/expansion/crowdstrike_falcon.py)
