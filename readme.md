# DNAC AP Location Manager

Python automation tool for managing Cisco Catalyst Center Access Point locations.

## Features

- Bulk AP location assignment from CSV
- Automatic device UUID lookup
- Site unassignment and reassignment workflow
- AP position retrieval and update
- Coordinate-based positioning (X, Y, Z)
- Comprehensive task monitoring and error handling
- Detailed CSV output with status tracking

## Requirements

- Python 3.x
- Cisco Catalyst Center (DNA Center) access
- Required Python packages: requests, urllib3

## Installation

'''
bash
pip install requests urllib3
'''

## CSV Format

'''csv
Device Name,New Floor,New X,New Y
AP-NAME-001,Global/Site/Building/Floor1,100.5,200.3
AP-NAME-002,Global/Site/Building/Floor2,150.0,250.0
'''

## Usage

'''bash
python dnac-ap-location.py --file devices.csv --dnac-ip <DNAC_IP> --username <USERNAME>
'''

## Output

Results are saved to \`devices_with_result.csv\` with detailed status columns for each workflow step.

## License

Copyright (c) 2021 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at
               https://developer.cisco.com/docs/licenses
All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.