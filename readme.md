# DNAC AP Location Manager

Python automation tool for managing Cisco Catalyst Center Access Point locations and positions.

## Features

- Two operation modes for different AP location management scenarios
- Bulk AP processing from CSV files
- Automatic device UUID and site ID lookup
- Coordinate-based positioning (X, Y)
- Comprehensive task monitoring and error handling
- Detailed CSV output with status tracking for all operations

## Requirements

- Python 3.x
- Cisco Catalyst Center (DNA Center) access
- Required Python packages: requests, urllib3

## Installation

`bash
pip install requests urllib3
`
or
`bash
pip install -r .\requirements.txt
`

## Operation Modes

### 1. Move AP to New Map (`move_new_map`)
Moves APs to new floor maps after location changes.

**Workflow:**
1. Lookup device UUIDs and new site IDs
2. Unassign devices from current sites
3. Assign devices to new sites/floors
4. Retrieve AP positions from new floors
5. Update AP positions with new X/Y coordinates

**CSV Format:**

| Device Name  | New Floor                        | New X | New Y |
|--------------|----------------------------------|-------|-------|
| AP-NAME-001  | Global/Site/Building/Floor1      | 100.5 | 200.3 |
| AP-NAME-002  | Global/Site/Building/Floor2      | 150.0 | 250.0 |

**Required Columns:** Device Name, New Floor, New X (optional), New Y (optional)

### 2. Update Positions on Existing Map (`move_existing_map`)
Updates AP positions on their current floor maps without relocating them.

**Workflow:**
1. Lookup device UUIDs from DNA Center
2. Get current floor IDs from existing device locations
3. Retrieve current AP positions
4. Update AP positions with new X/Y coordinates

**CSV Format:**

| Device Name  | New X | New Y |
|--------------|-------|-------|
| AP-NAME-001  | 120.5 | 210.3 |
| AP-NAME-002  | 160.0 | 260.0 |

**Required Columns:** Device Name, New X (optional), New Y (optional)

## Usage

### Move AP to New Map
`bash
python dnac-ap-location.py --file devices.csv --dnac-ip <DNAC_IP> --username <USERNAME> --option move_new_map
`

### Update Positions on Existing Map
`bash
python dnac-ap-location.py --file devices.csv --dnac-ip <DNAC_IP> --username <USERNAME> --option move_existing_map
`

### Command Line Arguments

| Argument       | Required | Description                                                |
|----------------|----------|------------------------------------------------------------|
| `-f, --file`   | Yes      | Path to CSV file containing device information             |
| `--dnac-ip`    | No       | DNA Center IP address (prompts if not provided)            |
| `--dnac-port`  | No       | DNA Center port (default: 443)                             |
| `--username`   | No       | DNA Center username (prompts if not provided)              |
| `--option`     | No       | Operation mode: `move_new_map` or `move_existing_map`      |

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