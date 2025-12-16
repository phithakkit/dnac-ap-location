@"
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

\`\`\`bash
pip install requests urllib3
\`\`\`

## CSV Format

\`\`\`csv
Device Name,New Floor,New X,New Y
AP-NAME-001,Global/Site/Building/Floor1,100.5,200.3
AP-NAME-002,Global/Site/Building/Floor2,150.0,250.0
\`\`\`

## Usage

\`\`\`bash
python dnac-ap-location.py --file devices.csv --dnac-ip <DNAC_IP> --username <USERNAME>
\`\`\`

## Configuration

Create \`dnac_config.py\` with:

\`\`\`python
DEBUG_LEVEL = 'INFO'
LOG_FILE = 'application_run.log'
DNAC_PORT = '443'
\`\`\`

## Output

Results are saved to \`devices_with_uuids.csv\` with detailed status columns for each workflow step.

## License

MIT License
"@ | Out-File -FilePath README.md -Encoding utf8