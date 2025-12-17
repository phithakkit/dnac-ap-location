from log_setup import log_setup
from dnac_restapi_lib import rest_api_lib
import getpass
import json
import time
import csv
import argparse
import logging
import sys


def main():
    
    DEBUG_LEVEL = 'DEBUG'
    LOG_FILE = 'application_run.log'
    DNAC_PORT = '443'
    parser = argparse.ArgumentParser(
        description='Assign AP to Location in Cisco Catalyst Center based on CSV input',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
    python dnac-ap-location.py -f devices.csv --dnac-ip 192.168.1.100 --username admin
        '''
    )
    
    parser.add_argument(
        '-f', '--file',
        type=str,
        required=True,
        help='Path to CSV file containing device names'
    )
    
    parser.add_argument(
        '--dnac-ip',
        type=str,
        help='DNA Center IP address (if not provided, will prompt)'
    )
    
    parser.add_argument(
        '--dnac-port',
        type=str,
        default=DNAC_PORT,
        help=f'DNA Center port (default: {DNAC_PORT})'
    )
    
    parser.add_argument(
        '--username',
        type=str,
        help='DNA Center username (if not provided, will prompt)'
    )
    
    parser.add_argument(
        '--option',
        type=str,
        choices=['move_new_map', 'move_existing_map'],
        help=(
            'Operation mode: '
            'move_new_map - Move AP to new map after location change, '
            'move_existing_map - Move AP on existing map'
        )
    )
    
    args = parser.parse_args()
    
    log_setup(DEBUG_LEVEL, LOG_FILE)
    
    # Check if CSV file exists
    try:
        with open(args.file, 'r') as f:
            pass
    except FileNotFoundError:
        print(f'Error: CSV file "{args.file}" not found.')
        sys.exit(1)
    except Exception as e:
        print(f'Error accessing CSV file: {e}')
        sys.exit(1)

    # Get DNA Center credentials
    dnac_ip = args.dnac_ip or input(f'Enter DNAC IP: ')
    dnac_port = args.dnac_port
    username = args.username or input('Enter DNAC username: ')
    password = getpass.getpass('Enter DNAC password: ')

    all_clients_data = []

    # Initialize DNA Center connection
    dnac = rest_api_lib(dnac_ip, dnac_port, username, password)
    
    # Read CSV file and get UUIDs
    print(f'\nReading device names from CSV file: {args.file}')
    if args.option == 'move_new_map':
        print('Operation Mode: Move AP to New Map after Location Change\n')
        result_data = new_map_locations_from_csv(dnac, args.file)
    if args.option == 'move_existing_map':
        print('Operation Mode: Move AP on Existing Map\n')
        result_data = existing_map_locations_from_csv(dnac, args.file)

def new_map_locations_from_csv(dnac, csv_file):
    '''
    Process AP location changes by moving APs to new maps/floors with updated positions.
    
    Operations performed:
    1. Read CSV and lookup device UUIDs and site IDs from DNA Center
    2. Unassign devices from current sites (if assigned)
    3. Assign devices to new sites/floors (batched, max 100 per request)
    4. Retrieve current AP positions from new floors
    5. Update AP positions with new X/Y coordinates from CSV (batched, max 100 per request)
    6. Save results with comprehensive status tracking
    
    Required CSV columns:
    - Device Name: AP hostname in DNA Center
    - New Floor: Target floor location path (e.g., Global/Site/Building/Floor1)
    - New X: New X coordinate for AP position (optional)
    - New Y: New Y coordinate for AP position (optional)
    
    Output CSV includes: Device UUID, Device IP, Current Location, Site IDs, 
    Unassign/Assign/Position Update status and task IDs for all operations.
    '''
    results = []
    
    try:
        with open(csv_file, 'r', encoding='utf-8-sig') as file:
            reader = csv.DictReader(file)
            fieldnames = reader.fieldnames or []
            
            # Validate required columns
            if 'Device Name' not in fieldnames:
                print(f'Error: CSV file must contain "Device Name" column')
                print(f'Found columns: {", ".join(fieldnames)}')
                return
            
            if 'New Floor' not in fieldnames:
                print(f'Error: CSV file must contain "New Floor" column')
                print(f'Found columns: {", ".join(fieldnames)}')
                return
            
            rows = list(reader)
            total_rows = len(rows)
            
            if total_rows == 0:
                print('No devices found in CSV file.')
                return
            
            print(f'\nFound {total_rows} device(s) to process\n')
            print('Fetching device UUIDs from DNA Center...')
            print('='*80)
            
            # Cache for site IDs to avoid duplicate queries
            site_id_cache = {}
            
            for i, row in enumerate(rows, 1):
                device_name = row.get('Device Name', '').strip()
                new_floor = row.get('New Floor', '').strip()
                
                if not device_name:
                    print(f'[{i}/{total_rows}] Row {i}: Skipping - missing device name')
                    row['Device UUID'] = 'ERROR: Missing Device UUID'
                    row['Get Device Status'] = 'Failed'
                    row['New Floor ID'] = 'ERROR: Missing Floor ID'
                    row['Get Site Status'] = 'Failed'
                    results.append(row)
                    continue
                
                if not new_floor:
                    print(f'[{i}/{total_rows}] Row {i}: Skipping - missing new floor')
                    row['Device UUID'] = 'ERROR: Missing Device UUID'
                    row['Get Device Status'] = 'Failed'
                    row['New Floor ID'] = 'ERROR: Missing new floor'
                    row['Get Site Status'] = 'Failed'
                    results.append(row)
                    continue
                
                print(f'[{i}/{total_rows}] Processing: {device_name} -> {new_floor}')
                
                # Query DNAC for device by name using get_device_detail
                device_detail = dnac.get_device_detail(identifier="nwDeviceName", searchBy=device_name)
                
                if device_detail is None:
                    print(f'  ✗ API Error or Not Found - Device "{device_name}" not found in DNA Center')
                    row['Device UUID'] = 'ERROR: Device UUID not found or API query failed'
                    row['Get Device Status'] = 'Not Found'
                    row['New Floor ID'] = 'ERROR: Floor ID not found'
                    row['Get Site Status'] = 'Failed'
                else:
                    # Extract device information from device_detail response
                    device_uuid = device_detail.get('nwDeviceId', 'None')
                    hostname = device_detail.get('nwDeviceName', device_name)
                    mgmt_ip = device_detail.get('managementIpAddr', 'N/A')
                    location = device_detail.get('location', 'None')
                    
                    print(f'  ✓ Found: {hostname} ({mgmt_ip})')
                    print(f'  ✓ UUID: {device_uuid}')
                    
                    row['Device UUID'] = device_uuid
                    row['Device IP'] = mgmt_ip
                    row['Current Device Location'] = location
                    row['Get Device Status'] = 'Success'
                
                # Get site ID for new floor location (use cache if available)
                if new_floor in site_id_cache:
                    site_id = site_id_cache[new_floor]
                    print(f'  → Using cached Site ID for: {new_floor}')
                    print(f'  ✓ Site ID: {site_id}')
                    row['New Floor ID'] = site_id
                    row['Get Site Status'] = 'Success (Cached)'
                else:
                    print(f'  → Fetching Site ID for: {new_floor}')
                    site_id = dnac.get_siteid_by_name(site_name=new_floor)
                    
                    if site_id:
                        print(f'  ✓ Site ID: {site_id}')
                        site_id_cache[new_floor] = site_id  # Cache for future use
                        row['New Floor ID'] = site_id
                        row['Get Site Status'] = 'Success'
                    else:
                        print(f'  ✗ Site Not Found - "{new_floor}" not found in DNA Center')
                        row['New Floor ID'] = 'ERROR: Site not found'
                        row['Get Site Status'] = 'Not Found'
                
                results.append(row)
            
            print('='*80)
            
            # Unassign devices from current site if they have a location
            print('\n' + '='*80)
            print('UNASSIGNING DEVICES FROM CURRENT SITES')
            print('='*80)
            
            devices_to_unassign = [r for r in results if r.get('Current Device Location') and 
                                   r.get('Current Device Location') not in ['None', 'N/A', ''] and
                                   r.get('Device UUID') and 
                                   not r.get('Device UUID', '').startswith('ERROR')]
            
            if devices_to_unassign:
                print(f'\nFound {len(devices_to_unassign)} device(s) with current site assignment')
                
                for i, device_row in enumerate(devices_to_unassign, 1):
                    device_uuid = device_row.get('Device UUID')
                    device_name = device_row.get('Device Name', 'Unknown')
                    current_location = device_row.get('Current Device Location')
                    
                    print(f'\n[{i}/{len(devices_to_unassign)}] Unassigning: {device_name}')
                    print(f'  Current Location: {current_location}')
                    print(f'  Device UUID: {device_uuid}')
                    
                    # Unassign device from site
                    unassign_result = dnac.unassign_device_from_site(device_ids=[device_uuid])
                    
                    if unassign_result and 'taskId' in unassign_result:
                        task_id = unassign_result['taskId']
                        print(f'  ✓ Unassign task created: {task_id}')
                        print(f'  → Monitoring task status...')
                        
                        # Poll task status until completion
                        max_wait = 120  # 2 minutes max wait
                        poll_interval = 5  # Check every 5 seconds
                        start_time = time.time()
                        
                        while time.time() - start_time < max_wait:
                            task_info = dnac.get_tasks_by_id(task_id)
                            
                            if task_info:
                                task_status = task_info.get('status', '').upper()
                                
                                if task_status == 'SUCCESS':
                                    print(f'  ✓ Unassign completed successfully')
                                    device_row['Unassign Status'] = 'Success'
                                    device_row['Unassign Task ID'] = task_id
                                    break
                                elif task_status == 'FAILURE':
                                    error_msg = task_info.get('failureReason', 'Unknown error')
                                    print(f'  ✗ Unassign failed: {error_msg}')
                                    device_row['Unassign Status'] = f'Failed: {error_msg}'
                                    device_row['Unassign Task ID'] = task_id
                                    break
                                else:
                                    print(f'  → Task status: {task_status}')
                                    time.sleep(poll_interval)
                            else:
                                print(f'  ! Warning: Could not retrieve task status')
                                time.sleep(poll_interval)
                        
                        # Check if we timed out
                        if time.time() - start_time >= max_wait:
                            print(f'  ! Timeout: Task did not complete within {max_wait} seconds')
                            device_row['Unassign Status'] = 'Timeout'
                            device_row['Unassign Task ID'] = task_id
                    else:
                        print(f'  ✗ Failed to create unassign task')
                        device_row['Unassign Status'] = 'Failed to create task'
                        device_row['Unassign Task ID'] = 'N/A'
            else:
                print('\nNo devices found with current site assignments to unassign')
            
            print('='*80)
            
            # Assign devices to new sites
            print('\n' + '='*80)
            print('ASSIGNING DEVICES TO NEW SITES')
            print('='*80)
            
            # Group devices by New Floor ID (site)
            devices_to_assign = {}
            for device_row in results:
                site_id = device_row.get('New Floor ID', '')
                device_uuid = device_row.get('Device UUID', '')
                
                # Only include devices with valid site IDs and UUIDs
                if (site_id and 
                    not site_id.startswith('ERROR') and 
                    device_uuid and 
                    not device_uuid.startswith('ERROR')):
                    
                    if site_id not in devices_to_assign:
                        devices_to_assign[site_id] = []
                    devices_to_assign[site_id].append(device_row)
            
            if devices_to_assign:
                print(f'\nFound {sum(len(v) for v in devices_to_assign.values())} device(s) ready to assign to {len(devices_to_assign)} site(s)')
                
                site_num = 0
                
                for site_id, device_list in devices_to_assign.items():
                    site_num += 1
                    site_name = device_list[0].get('New Floor', 'Unknown')
                    
                    print(f'\n{"="*80}')
                    print(f'SITE GROUP {site_num}/{len(devices_to_assign)}: {site_name}')
                    print(f'Site ID: {site_id}')
                    print(f'Devices to assign: {len(device_list)}')
                    print(f'{"="*80}')
                    
                    # Process in batches of 100 (API limit)
                    batch_size = 100
                    for batch_num in range(0, len(device_list), batch_size):
                        batch = device_list[batch_num:batch_num + batch_size]
                        batch_device_ids = [d.get('Device UUID') for d in batch]
                        
                        print(f'\nBatch {batch_num//batch_size + 1}: Assigning {len(batch)} device(s)...')
                        for d in batch:
                            print(f'  - {d.get("Device Name", "Unknown")} ({d.get("Device UUID")})')
                        
                        # Assign devices to site
                        assign_result = dnac.assign_devices_to_site(
                            site_id=site_id,
                            device_ids=batch_device_ids
                        )
                        
                        if assign_result and 'taskId' in assign_result:
                            task_id = assign_result['taskId']
                            print(f'  ✓ Assign task created: {task_id}')
                            print(f'  → Monitoring task status...')
                            
                            # Poll task status until completion
                            max_wait = 120  # 2 minutes max wait
                            poll_interval = 5  # Check every 5 seconds
                            start_time = time.time()
                            
                            task_success = False
                            while time.time() - start_time < max_wait:
                                task_info = dnac.get_tasks_by_id(task_id)
                                
                                if task_info:
                                    task_status = task_info.get('status', '').upper()
                                    
                                    if task_status == 'SUCCESS':
                                        print(f'  ✓ Assign completed successfully')
                                        task_success = True
                                        # Update all devices in this batch
                                        for device_row in batch:
                                            device_row['Assign Status'] = 'Success'
                                            device_row['Assign Task ID'] = task_id
                                        break
                                    elif task_status == 'FAILURE':
                                        error_msg = task_info.get('failureReason', 'Unknown error')
                                        print(f'  ✗ Assign failed: {error_msg}')
                                        # Update all devices in this batch
                                        for device_row in batch:
                                            device_row['Assign Status'] = f'Failed: {error_msg}'
                                            device_row['Assign Task ID'] = task_id
                                        break
                                    else:
                                        print(f'  → Task status: {task_status}')
                                        time.sleep(poll_interval)
                                else:
                                    print(f'  ! Warning: Could not retrieve task status')
                                    time.sleep(poll_interval)
                            
                            # Check if we timed out
                            if time.time() - start_time >= max_wait:
                                print(f'  ! Timeout: Task did not complete within {max_wait} seconds')
                                for device_row in batch:
                                    device_row['Assign Status'] = 'Timeout'
                                    device_row['Assign Task ID'] = task_id
                        else:
                            print(f'  ✗ Failed to create assign task')
                            for device_row in batch:
                                device_row['Assign Status'] = 'Failed to create task'
                                device_row['Assign Task ID'] = 'N/A'
                
                print(f'\n{"="*80}')
                print(f'ASSIGNMENT COMPLETE')
                print(f'{"="*80}')
            else:
                print('\nNo devices ready to assign (missing valid Site IDs or Device UUIDs)')
            
            print('='*80)
            
            # Retrieve AP positions for all new sites
            print('\n' + '='*80)
            print('RETRIEVING AP POSITIONS FROM NEW SITES')
            print('='*80)
            
            # Get unique floor IDs that were successfully assigned
            successfully_assigned_floors = {}
            for device_row in results:
                assign_status = device_row.get('Assign Status', '')
                floor_id = device_row.get('New Floor ID', '')
                floor_name = device_row.get('New Floor', '')
                device_name = device_row.get('Device Name', '')
                
                # Only get positions for successfully assigned devices
                if (assign_status == 'Success' and 
                    floor_id and 
                    not floor_id.startswith('ERROR')):
                    
                    if floor_id not in successfully_assigned_floors:
                        successfully_assigned_floors[floor_id] = {
                            'name': floor_name,
                            'devices': []
                        }
                    successfully_assigned_floors[floor_id]['devices'].append(device_row)
            
            if successfully_assigned_floors:
                print(f'\nRetrieving AP positions for {len(successfully_assigned_floors)} floor(s)')
                
                for floor_id, floor_info in successfully_assigned_floors.items():
                    floor_name = floor_info['name']
                    device_list = floor_info['devices']
                    
                    print(f'\n{"="*80}')
                    print(f'Floor: {floor_name}')
                    print(f'Floor ID: {floor_id}')
                    print(f'{"="*80}')
                    
                    print(f'  → Fetching AP positions...')
                    ap_positions = dnac.get_access_points_positions(floor_id=floor_id)
                    
                    if ap_positions is not None:
                        if isinstance(ap_positions, list) and len(ap_positions) > 0:
                            print(f'  ✓ Retrieved {len(ap_positions)} AP position(s)')
                            
                            # Create a lookup dictionary by device name or MAC address
                            ap_position_map = {}
                            for ap_pos in ap_positions:
                                # Try to map by name first
                                ap_name = ap_pos.get('name', '')
                                ap_mac = ap_pos.get('macAddress', '')
                                
                                if ap_name:
                                    ap_position_map[ap_name] = ap_pos
                                if ap_mac:
                                    ap_position_map[ap_mac] = ap_pos
                            
                            # Update device rows with AP position data
                            for device_row in device_list:
                                device_name = device_row.get('Device Name', '')
                                device_uuid = device_row.get('Device UUID', '')
                                
                                # Try to find matching AP position data
                                ap_pos_data = ap_position_map.get(device_name)
                                
                                if ap_pos_data:
                                    print(f'  ✓ Found position for: {device_name}')
                                    # Store position as dictionary
                                    device_row['AP Position'] = ap_pos_data.get('position', {})
                                    # Store radios as list
                                    device_row['AP Radios'] = ap_pos_data.get('radios', [])
                                    device_row['AP Position Status'] = 'Retrieved'
                                else:
                                    print(f'  ✗ No position found for: {device_name}')
                                    device_row['AP Position'] = {}
                                    device_row['AP Radios'] = []
                                    device_row['AP Position Status'] = 'Not Found'
                        else:
                            print(f'  ! No AP positions found for this floor')
                            for device_row in device_list:
                                device_row['AP Position'] = {}
                                device_row['AP Radios'] = []
                                device_row['AP Position Status'] = 'No Data'
                    else:
                        print(f'  ✗ Failed to retrieve AP positions')
                        for device_row in device_list:
                            device_row['AP Position'] = {}
                            device_row['AP Radios'] = []
                            device_row['AP Position Status'] = 'API Error'
                
                print(f'\n{"="*80}')
                print(f'AP POSITION RETRIEVAL COMPLETE')
                print(f'{"="*80}')
            else:
                print('\nNo successfully assigned devices to retrieve AP positions for')
            
            print('='*80)
            
            # Update AP positions for all floors
            print('\n' + '='*80)
            print('UPDATING AP POSITIONS')
            print('='*80)
            
            # Group devices by floor_id that have valid position data
            floors_to_update = {}
            for device_row in results:
                ap_position_status = device_row.get('AP Position Status', '')
                floor_id = device_row.get('New Floor ID', '')
                floor_name = device_row.get('New Floor', '')
                
                # Only include devices with retrieved position data and valid floor IDs
                if (ap_position_status == 'Retrieved' and 
                    floor_id and 
                    not floor_id.startswith('ERROR')):
                    
                    if floor_id not in floors_to_update:
                        floors_to_update[floor_id] = {
                            'name': floor_name,
                            'devices': []
                        }
                    floors_to_update[floor_id]['devices'].append(device_row)
            
            if floors_to_update:
                print(f'\nPreparing to update AP positions for {len(floors_to_update)} floor(s)')
                
                floor_num = 0
                
                for floor_id, floor_info in floors_to_update.items():
                    floor_num += 1
                    floor_name = floor_info['name']
                    device_list = floor_info['devices']
                    
                    # Build payload with devices that have position data
                    aps_to_update = []
                    device_map = {}  # Map to track which devices are in which batch
                    
                    for device_row in device_list:
                        ap_position = device_row.get('AP Position')
                        ap_radios = device_row.get('AP Radios')
                        device_uuid = device_row.get('Device UUID', '')
                        device_name = device_row.get('Device Name', '')
                        new_x = device_row.get('New X', '')
                        new_y = device_row.get('New Y', '')
                        
                        if ap_position and device_uuid:
                            # Update position with new X and Y coordinates from CSV
                            updated_position = ap_position.copy()
                            
                            # Convert new X and Y to float if provided
                            try:
                                if new_x:
                                    updated_position['x'] = float(new_x)
                                if new_y:
                                    updated_position['y'] = float(new_y)
                            except (ValueError, TypeError) as e:
                                logging.warning(f'Invalid X/Y coordinates for {device_name}: X={new_x}, Y={new_y}')
                            
                            ap_update_data = {
                                'id': device_uuid,
                                'position': updated_position
                            }
                            
                            # Include radios if available
                            if ap_radios:
                                ap_update_data['radios'] = ap_radios
                            
                            aps_to_update.append(ap_update_data)
                            device_map[device_uuid] = device_row
                    
                    if aps_to_update:
                        print(f'\n{"="*80}')
                        print(f'FLOOR {floor_num}/{len(floors_to_update)}: {floor_name}')
                        print(f'Floor ID: {floor_id}')
                        print(f'APs to update: {len(aps_to_update)}')
                        print(f'{"="*80}')
                        
                        # Process in batches of 100 (API limit)
                        batch_size = 100
                        for batch_num in range(0, len(aps_to_update), batch_size):
                            batch_aps = aps_to_update[batch_num:batch_num + batch_size]
                            
                            print(f'\nBatch {batch_num//batch_size + 1}: Updating {len(batch_aps)} AP(s)...')
                            for ap_data in batch_aps:
                                print(f'  - Device ID: {ap_data.get("id", "Unknown")}')
                            
                            print(f'\n  → Updating AP positions...')
                            
                            # Call the edit_access_points_positions API
                            update_result = dnac.edit_access_points_positions(
                                floor_id=floor_id,
                                positions_data=batch_aps
                            )
                            
                            if update_result:
                                if 'taskId' in update_result:
                                    task_id = update_result['taskId']
                                    print(f'  ✓ Update task created: {task_id}')
                                    print(f'  → Monitoring task status...')
                                    
                                    # Poll task status until completion
                                    max_wait = 120  # 2 minutes max wait
                                    poll_interval = 5  # Check every 5 seconds
                                    start_time = time.time()
                                    
                                    while time.time() - start_time < max_wait:
                                        task_info = dnac.get_tasks_by_id(task_id)
                                        
                                        if task_info:
                                            task_status = task_info.get('status', '').upper()
                                            
                                            if task_status == 'SUCCESS':
                                                print(f'  ✓ AP positions updated successfully')
                                                # Update status for devices in this batch
                                                for ap_data in batch_aps:
                                                    device_uuid = ap_data.get('id')
                                                    if device_uuid in device_map:
                                                        device_map[device_uuid]['AP Update Status'] = 'Success'
                                                        device_map[device_uuid]['AP Update Task ID'] = task_id
                                                break
                                            elif task_status == 'FAILURE':
                                                error_msg = task_info.get('failureReason', 'Unknown error')
                                                print(f'  ✗ Update failed: {error_msg}')
                                                for ap_data in batch_aps:
                                                    device_uuid = ap_data.get('id')
                                                    if device_uuid in device_map:
                                                        device_map[device_uuid]['AP Update Status'] = f'Failed: {error_msg}'
                                                        device_map[device_uuid]['AP Update Task ID'] = task_id
                                                break
                                            else:
                                                print(f'  → Task status: {task_status}')
                                                time.sleep(poll_interval)
                                        else:
                                            print(f'  ! Warning: Could not retrieve task status')
                                            time.sleep(poll_interval)
                                    
                                    # Check if we timed out
                                    if time.time() - start_time >= max_wait:
                                        print(f'  ! Timeout: Task did not complete within {max_wait} seconds')
                                        for ap_data in batch_aps:
                                            device_uuid = ap_data.get('id')
                                            if device_uuid in device_map:
                                                device_map[device_uuid]['AP Update Status'] = 'Timeout'
                                                device_map[device_uuid]['AP Update Task ID'] = task_id
                                else:
                                    print(f'  ✓ AP positions updated (no task tracking)')
                                    for ap_data in batch_aps:
                                        device_uuid = ap_data.get('id')
                                        if device_uuid in device_map:
                                            device_map[device_uuid]['AP Update Status'] = 'Success (Direct)'
                                            device_map[device_uuid]['AP Update Task ID'] = 'N/A'
                            else:
                                print(f'  ✗ Failed to update AP positions')
                                for ap_data in batch_aps:
                                    device_uuid = ap_data.get('id')
                                    if device_uuid in device_map:
                                        device_map[device_uuid]['AP Update Status'] = 'Failed to create request'
                                        device_map[device_uuid]['AP Update Task ID'] = 'N/A'
                    else:
                        print(f'\n{"="*80}')
                        print(f'FLOOR {floor_num}/{len(floors_to_update)}: {floor_name}')
                        print(f'  ! No APs with valid position data to update')
                        print(f'{"="*80}')
                
                print(f'\n{"="*80}')
                print(f'AP POSITION UPDATE COMPLETE')
                print(f'{"="*80}')
            else:
                print('\nNo devices with valid position data to update')
            
            print('='*80)
            
            # Save updated CSV with UUIDs
            logging.debug(f'devices_with_uuids: {json.dumps(results, indent=2)}')
            logging.info(f'\nSaving results to CSV file with UUIDs...')
            save_devices_with_uuids(results, fieldnames)
            logging.info(f'\nFinished saving results to CSV file with UUIDs...')
            
            # Print comprehensive summary
            print('\n' + '='*80)
            print('PROCESSING SUMMARY')
            print('='*80)
            
            # Device Lookup Statistics
            total_devices = len(results)
            uuid_success = sum(1 for r in results if r.get('Get Device Status') == 'Success' or 'Success' in r.get('Get Device Status', ''))
            uuid_not_found = sum(1 for r in results if r.get('Get Device Status') == 'Not Found')
            uuid_failed = sum(1 for r in results if r.get('Get Device Status') == 'Failed')
            
            print(f'\n1. DEVICE LOOKUP:')
            print(f'   Total devices processed: {total_devices}')
            print(f'   ✓ UUIDs retrieved: {uuid_success}')
            print(f'   ✗ Not found: {uuid_not_found}')
            print(f'   ✗ Failed: {uuid_failed}')
            
            # Site ID Lookup Statistics
            site_success = sum(1 for r in results if 'Success' in r.get('Get Site Status', ''))
            site_not_found = sum(1 for r in results if r.get('Get Site Status') == 'Not Found')
            site_failed = sum(1 for r in results if r.get('Get Site Status') == 'Failed')
            
            print(f'\n2. SITE ID LOOKUP:')
            print(f'   ✓ Site IDs retrieved: {site_success}')
            print(f'   ✗ Not found: {site_not_found}')
            print(f'   ✗ Failed: {site_failed}')
            
            # Unassignment Statistics
            unassign_attempted = sum(1 for r in results if r.get('Unassign Status'))
            unassign_success = sum(1 for r in results if r.get('Unassign Status') == 'Success')
            unassign_timeout = sum(1 for r in results if r.get('Unassign Status') == 'Timeout')
            unassign_failed = sum(1 for r in results if r.get('Unassign Status', '').startswith('Failed'))
            
            print(f'\n3. DEVICE UNASSIGNMENT:')
            print(f'   Devices with current assignment: {unassign_attempted}')
            print(f'   ✓ Successfully unassigned: {unassign_success}')
            print(f'   ⏱ Timeout: {unassign_timeout}')
            print(f'   ✗ Failed: {unassign_failed}')
            
            # Assignment Statistics
            assign_attempted = sum(1 for r in results if r.get('Assign Status'))
            assign_success = sum(1 for r in results if r.get('Assign Status') == 'Success')
            assign_timeout = sum(1 for r in results if r.get('Assign Status') == 'Timeout')
            assign_failed = sum(1 for r in results if r.get('Assign Status', '').startswith('Failed'))
            
            print(f'\n4. DEVICE ASSIGNMENT:')
            print(f'   Devices ready for assignment: {assign_attempted}')
            print(f'   ✓ Successfully assigned: {assign_success}')
            print(f'   ⏱ Timeout: {assign_timeout}')
            print(f'   ✗ Failed: {assign_failed}')
            
            # AP Position Retrieval Statistics
            ap_position_retrieved = sum(1 for r in results if r.get('AP Position Status') == 'Retrieved')
            ap_position_not_found = sum(1 for r in results if r.get('AP Position Status') == 'Not Found')
            ap_position_no_data = sum(1 for r in results if r.get('AP Position Status') == 'No Data')
            ap_position_error = sum(1 for r in results if r.get('AP Position Status') == 'API Error')
            
            print(f'\n5. AP POSITION RETRIEVAL:')
            print(f'   ✓ Positions retrieved: {ap_position_retrieved}')
            print(f'   ✗ Not found on floor: {ap_position_not_found}')
            print(f'   ! No data available: {ap_position_no_data}')
            print(f'   ✗ API error: {ap_position_error}')
            
            # AP Position Update Statistics
            ap_update_attempted = sum(1 for r in results if r.get('AP Update Status'))
            ap_update_success = sum(1 for r in results if 'Success' in r.get('AP Update Status', ''))
            ap_update_timeout = sum(1 for r in results if r.get('AP Update Status') == 'Timeout')
            ap_update_failed = sum(1 for r in results if r.get('AP Update Status', '').startswith('Failed'))
            
            print(f'\n6. AP POSITION UPDATE:')
            print(f'   APs with position data: {ap_update_attempted}')
            print(f'   ✓ Successfully updated: {ap_update_success}')
            print(f'   ⏱ Timeout: {ap_update_timeout}')
            print(f'   ✗ Failed: {ap_update_failed}')
            
            # Overall Status
            fully_successful = sum(1 for r in results if 
                                  r.get('Get Device Status') == 'Success' and
                                  'Success' in r.get('Get Site Status', '') and
                                  r.get('Assign Status') == 'Success' and
                                  'Success' in r.get('AP Update Status', ''))
            
            print(f'\n7. OVERALL:')
            print(f'   ✓ Fully completed (all steps): {fully_successful}/{total_devices}')
            print(f'   Success rate: {(fully_successful/total_devices*100):.1f}%' if total_devices > 0 else '   Success rate: N/A')
            
            print('='*80)
            
        return results
            
    except Exception as e:
        print(f'Error processing CSV file: {e}')
        import traceback
        traceback.print_exc()
        
def existing_map_locations_from_csv(dnac, csv_file):
    '''
    Process AP position updates on existing maps/floors without moving APs to new locations.
    
    Operations performed:
    1. Read CSV and lookup device UUIDs from DNA Center
    2. Get current floor IDs from existing device locations
    3. Retrieve current AP positions from existing floors
    4. Update AP positions with new X/Y coordinates from CSV (batched, max 100 per request)
    5. Save results with comprehensive status tracking
    
    Required CSV columns:
    - Device Name: AP hostname in DNA Center
    - New X: New X coordinate for AP position (optional)
    - New Y: New Y coordinate for AP position (optional)
    
    Output CSV includes: Device UUID, Device IP, Current Location, Floor IDs, 
    Position Retrieval/Update status and task IDs for all operations.
    '''
    results = []
    
    try:
        with open(csv_file, 'r', encoding='utf-8-sig') as file:
            reader = csv.DictReader(file)
            fieldnames = reader.fieldnames or []
            
            # Validate required columns
            if 'Device Name' not in fieldnames:
                print(f'Error: CSV file must contain "Device Name" column')
                print(f'Found columns: {", ".join(fieldnames)}')
                return
            
            rows = list(reader)
            total_rows = len(rows)
            
            if total_rows == 0:
                print('No devices found in CSV file.')
                return
            
            print(f'\nFound {total_rows} device(s) to process\n')
            print('Fetching device UUIDs from DNA Center...')
            print('='*80)
            
            # Cache for site IDs to avoid duplicate queries
            site_id_cache = {}
            
            for i, row in enumerate(rows, 1):
                device_name = row.get('Device Name', '').strip()
                
                if not device_name:
                    print(f'[{i}/{total_rows}] Row {i}: Skipping - missing device name')
                    row['Device UUID'] = 'ERROR: Missing Device UUID'
                    row['Get Device Status'] = 'Failed'
                    results.append(row)
                    continue
                
                print(f'[{i}/{total_rows}] Processing: {device_name}')
                
                # Query DNAC for device by name using get_device_detail
                device_detail = dnac.get_device_detail(identifier="nwDeviceName", searchBy=device_name)
                
                if device_detail is None:
                    print(f'  ✗ API Error or Not Found - Device "{device_name}" not found in DNA Center')
                    row['Device UUID'] = 'ERROR: Device UUID not found or API query failed'
                    row['Get Device Status'] = 'Not Found'
                    row['Floor ID'] = 'ERROR: Floor ID not found'
                else:
                    # Extract device information from device_detail response
                    device_uuid = device_detail.get('nwDeviceId', 'None')
                    hostname = device_detail.get('nwDeviceName', device_name)
                    mgmt_ip = device_detail.get('managementIpAddr', 'N/A')
                    location = device_detail.get('location', 'None')
                    
                    print(f'  ✓ Found: {hostname} ({mgmt_ip})')
                    print(f'  ✓ UUID: {device_uuid}')
                    
                    row['Device UUID'] = device_uuid
                    row['Device IP'] = mgmt_ip
                    row['Current Device Location'] = location
                    row['Get Device Status'] = 'Success'
                    
                    # Get site ID for current location (use cache if available)
                    if location and location not in ['None', 'N/A', '']:
                        if location in site_id_cache:
                            site_id = site_id_cache[location]
                            print(f'  → Using cached Site ID for: {location}')
                            print(f'  ✓ Site ID: {site_id}')
                            row['Floor ID'] = site_id
                            row['Get Site Status'] = 'Success (Cached)'
                        else:
                            print(f'  → Fetching Site ID for: {location}')
                            site_id = dnac.get_siteid_by_name(site_name=location)
                            
                            if site_id:
                                print(f'  ✓ Site ID: {site_id}')
                                site_id_cache[location] = site_id  # Cache for future use
                                row['Floor ID'] = site_id
                                row['Get Site Status'] = 'Success'
                            else:
                                print(f'  ✗ Site Not Found - "{location}" not found in DNA Center')
                                row['Floor ID'] = 'ERROR: Site not found'
                                row['Get Site Status'] = 'Not Found'
                    else:
                        print(f'  ! No current location available')
                        row['Floor ID'] = 'ERROR: No location'
                        row['Get Site Status'] = 'No Location'
                
                results.append(row)
            
            print('='*80)
            
            # Retrieve AP positions for current sites
            print('\n' + '='*80)
            print('RETRIEVING AP POSITIONS FROM CURRENT SITES')
            print('='*80)
            
            # Get unique floor IDs from current locations
            floors_with_devices = {}
            for device_row in results:
                floor_id = device_row.get('Floor ID', '')
                floor_name = device_row.get('Current Device Location', '')
                device_name = device_row.get('Device Name', '')
                
                # Only get positions for devices with valid floor IDs
                if (floor_id and 
                    not floor_id.startswith('ERROR')):
                    
                    if floor_id not in floors_with_devices:
                        floors_with_devices[floor_id] = {
                            'name': floor_name,
                            'devices': []
                        }
                    floors_with_devices[floor_id]['devices'].append(device_row)
            
            if floors_with_devices:
                print(f'\nRetrieving AP positions for {len(floors_with_devices)} floor(s)')
                
                for floor_id, floor_info in floors_with_devices.items():
                    floor_name = floor_info['name']
                    device_list = floor_info['devices']
                    
                    print(f'\n{"="*80}')
                    print(f'Floor: {floor_name}')
                    print(f'Floor ID: {floor_id}')
                    print(f'{"="*80}')
                    
                    print(f'  → Fetching AP positions...')
                    ap_positions = dnac.get_access_points_positions(floor_id=floor_id)
                    
                    if ap_positions is not None:
                        if isinstance(ap_positions, list) and len(ap_positions) > 0:
                            print(f'  ✓ Retrieved {len(ap_positions)} AP position(s)')
                            
                            # Create a lookup dictionary by device name or MAC address
                            ap_position_map = {}
                            for ap_pos in ap_positions:
                                # Try to map by name first
                                ap_name = ap_pos.get('name', '')
                                ap_mac = ap_pos.get('macAddress', '')
                                
                                if ap_name:
                                    ap_position_map[ap_name] = ap_pos
                                if ap_mac:
                                    ap_position_map[ap_mac] = ap_pos
                            
                            # Update device rows with AP position data
                            for device_row in device_list:
                                device_name = device_row.get('Device Name', '')
                                device_uuid = device_row.get('Device UUID', '')
                                
                                # Try to find matching AP position data
                                ap_pos_data = ap_position_map.get(device_name)
                                
                                if ap_pos_data:
                                    print(f'  ✓ Found position for: {device_name}')
                                    # Store position as dictionary
                                    device_row['AP Position'] = ap_pos_data.get('position', {})
                                    # Store radios as list
                                    device_row['AP Radios'] = ap_pos_data.get('radios', [])
                                    device_row['AP Position Status'] = 'Retrieved'
                                else:
                                    print(f'  ✗ No position found for: {device_name}')
                                    device_row['AP Position'] = {}
                                    device_row['AP Radios'] = []
                                    device_row['AP Position Status'] = 'Not Found'
                        else:
                            print(f'  ! No AP positions found for this floor')
                            for device_row in device_list:
                                device_row['AP Position'] = {}
                                device_row['AP Radios'] = []
                                device_row['AP Position Status'] = 'No Data'
                    else:
                        print(f'  ✗ Failed to retrieve AP positions')
                        for device_row in device_list:
                            device_row['AP Position'] = {}
                            device_row['AP Radios'] = []
                            device_row['AP Position Status'] = 'API Error'
                
                print(f'\n{"="*80}')
                print(f'AP POSITION RETRIEVAL COMPLETE')
                print(f'{"="*80}')
            else:
                print('\nNo devices with valid floor IDs to retrieve AP positions for')
            
            # Update AP positions for current floors
            print('\n' + '='*80)
            print('UPDATING AP POSITIONS')
            print('='*80)
            
            # Group devices by floor_id that have valid position data
            floors_to_update = {}
            for device_row in results:
                ap_position_status = device_row.get('AP Position Status', '')
                floor_id = device_row.get('Floor ID', '')
                floor_name = device_row.get('Current Device Location', '')
                
                # Only include devices with retrieved position data and valid floor IDs
                if (ap_position_status == 'Retrieved' and 
                    floor_id and 
                    not floor_id.startswith('ERROR')):
                    
                    if floor_id not in floors_to_update:
                        floors_to_update[floor_id] = {
                            'name': floor_name,
                            'devices': []
                        }
                    floors_to_update[floor_id]['devices'].append(device_row)
            
            if floors_to_update:
                print(f'\nPreparing to update AP positions for {len(floors_to_update)} floor(s)')
                
                floor_num = 0
                
                for floor_id, floor_info in floors_to_update.items():
                    floor_num += 1
                    floor_name = floor_info['name']
                    device_list = floor_info['devices']
                    
                    # Build payload with devices that have position data
                    aps_to_update = []
                    device_map = {}  # Map to track which devices are in which batch
                    
                    for device_row in device_list:
                        ap_position = device_row.get('AP Position')
                        ap_radios = device_row.get('AP Radios')
                        device_uuid = device_row.get('Device UUID', '')
                        device_name = device_row.get('Device Name', '')
                        new_x = device_row.get('New X', '')
                        new_y = device_row.get('New Y', '')
                        
                        if ap_position and device_uuid:
                            # Update position with new X and Y coordinates from CSV
                            updated_position = ap_position.copy()
                            
                            # Convert new X and Y to float if provided
                            try:
                                if new_x:
                                    updated_position['x'] = float(new_x)
                                if new_y:
                                    updated_position['y'] = float(new_y)
                            except (ValueError, TypeError) as e:
                                logging.warning(f'Invalid X/Y coordinates for {device_name}: X={new_x}, Y={new_y}')
                            
                            ap_update_data = {
                                'id': device_uuid,
                                'position': updated_position
                            }
                            
                            # Include radios if available
                            if ap_radios:
                                ap_update_data['radios'] = ap_radios
                            
                            aps_to_update.append(ap_update_data)
                            device_map[device_uuid] = device_row
                    
                    if aps_to_update:
                        print(f'\n{"="*80}')
                        print(f'FLOOR {floor_num}/{len(floors_to_update)}: {floor_name}')
                        print(f'Floor ID: {floor_id}')
                        print(f'APs to update: {len(aps_to_update)}')
                        print(f'{"="*80}')
                        
                        # Process in batches of 100 (API limit)
                        batch_size = 100
                        for batch_num in range(0, len(aps_to_update), batch_size):
                            batch_aps = aps_to_update[batch_num:batch_num + batch_size]
                            
                            print(f'\nBatch {batch_num//batch_size + 1}: Updating {len(batch_aps)} AP(s)...')
                            for ap_data in batch_aps:
                                print(f'  - Device ID: {ap_data.get("id", "Unknown")}')
                            
                            print(f'\n  → Updating AP positions...')
                            
                            # Call the edit_access_points_positions API
                            update_result = dnac.edit_access_points_positions(
                                floor_id=floor_id,
                                positions_data=batch_aps
                            )
                            
                            if update_result:
                                if 'taskId' in update_result:
                                    task_id = update_result['taskId']
                                    print(f'  ✓ Update task created: {task_id}')
                                    print(f'  → Monitoring task status...')
                                    
                                    # Poll task status until completion
                                    max_wait = 120  # 2 minutes max wait
                                    poll_interval = 5  # Check every 5 seconds
                                    start_time = time.time()
                                    
                                    while time.time() - start_time < max_wait:
                                        task_info = dnac.get_tasks_by_id(task_id)
                                        
                                        if task_info:
                                            task_status = task_info.get('status', '').upper()
                                            
                                            if task_status == 'SUCCESS':
                                                print(f'  ✓ AP positions updated successfully')
                                                # Update status for devices in this batch
                                                for ap_data in batch_aps:
                                                    device_uuid = ap_data.get('id')
                                                    if device_uuid in device_map:
                                                        device_map[device_uuid]['AP Update Status'] = 'Success'
                                                        device_map[device_uuid]['AP Update Task ID'] = task_id
                                                break
                                            elif task_status == 'FAILURE':
                                                error_msg = task_info.get('failureReason', 'Unknown error')
                                                print(f'  ✗ Update failed: {error_msg}')
                                                for ap_data in batch_aps:
                                                    device_uuid = ap_data.get('id')
                                                    if device_uuid in device_map:
                                                        device_map[device_uuid]['AP Update Status'] = f'Failed: {error_msg}'
                                                        device_map[device_uuid]['AP Update Task ID'] = task_id
                                                break
                                            else:
                                                print(f'  → Task status: {task_status}')
                                                time.sleep(poll_interval)
                                        else:
                                            print(f'  ! Warning: Could not retrieve task status')
                                            time.sleep(poll_interval)
                                    
                                    # Check if we timed out
                                    if time.time() - start_time >= max_wait:
                                        print(f'  ! Timeout: Task did not complete within {max_wait} seconds')
                                        for ap_data in batch_aps:
                                            device_uuid = ap_data.get('id')
                                            if device_uuid in device_map:
                                                device_map[device_uuid]['AP Update Status'] = 'Timeout'
                                                device_map[device_uuid]['AP Update Task ID'] = task_id
                                else:
                                    print(f'  ✓ AP positions updated (no task tracking)')
                                    for ap_data in batch_aps:
                                        device_uuid = ap_data.get('id')
                                        if device_uuid in device_map:
                                            device_map[device_uuid]['AP Update Status'] = 'Success (Direct)'
                                            device_map[device_uuid]['AP Update Task ID'] = 'N/A'
                            else:
                                print(f'  ✗ Failed to update AP positions')
                                for ap_data in batch_aps:
                                    device_uuid = ap_data.get('id')
                                    if device_uuid in device_map:
                                        device_map[device_uuid]['AP Update Status'] = 'Failed to create request'
                                        device_map[device_uuid]['AP Update Task ID'] = 'N/A'
                    else:
                        print(f'\n{"="*80}')
                        print(f'FLOOR {floor_num}/{len(floors_to_update)}: {floor_name}')
                        print(f'  ! No APs with valid position data to update')
                        print(f'{"="*80}')
                
                print(f'\n{"="*80}')
                print(f'AP POSITION UPDATE COMPLETE')
                print(f'{"="*80}')
            else:
                print('\nNo devices with valid position data to update')
            
            print(f'\n{"="*80}')
            print('SAVING RESULTS')
            print('='*80)
            
            # Save updated CSV with UUIDs
            logging.debug(f'devices_with_uuids: {json.dumps(results, indent=2)}')
            logging.info(f'\nSaving results to CSV file with UUIDs...')
            save_devices_with_uuids(results, fieldnames)
            logging.info(f'\nFinished saving results to CSV file with UUIDs...')
            
            # Print comprehensive summary
            print('\n' + '='*80)
            print('PROCESSING SUMMARY')
            print('='*80)
            
            # Device Lookup Statistics
            total_devices = len(results)
            uuid_success = sum(1 for r in results if r.get('Get Device Status') == 'Success' or 'Success' in r.get('Get Device Status', ''))
            uuid_not_found = sum(1 for r in results if r.get('Get Device Status') == 'Not Found')
            uuid_failed = sum(1 for r in results if r.get('Get Device Status') == 'Failed')
            
            print(f'\n1. DEVICE LOOKUP:')
            print(f'   Total devices processed: {total_devices}')
            print(f'   ✓ UUIDs retrieved: {uuid_success}')
            print(f'   ✗ Not found: {uuid_not_found}')
            print(f'   ✗ Failed: {uuid_failed}')
            
            # Site ID Lookup Statistics (Current Location)
            site_success = sum(1 for r in results if 'Success' in r.get('Get Site Status', ''))
            site_not_found = sum(1 for r in results if r.get('Get Site Status') == 'Not Found')
            site_failed = sum(1 for r in results if r.get('Get Site Status') == 'Failed')
            
            print(f'\n2. CURRENT SITE ID LOOKUP:')
            print(f'   ✓ Site IDs retrieved: {site_success}')
            print(f'   ✗ Not found: {site_not_found}')
            print(f'   ✗ Failed: {site_failed}')
            
            # AP Position Retrieval Statistics
            ap_position_retrieved = sum(1 for r in results if r.get('AP Position Status') == 'Retrieved')
            ap_position_not_found = sum(1 for r in results if r.get('AP Position Status') == 'Not Found')
            ap_position_no_data = sum(1 for r in results if r.get('AP Position Status') == 'No Data')
            ap_position_error = sum(1 for r in results if r.get('AP Position Status') == 'API Error')
            
            print(f'\n3. AP POSITION RETRIEVAL:')
            print(f'   ✓ Positions retrieved: {ap_position_retrieved}')
            print(f'   ✗ Not found on floor: {ap_position_not_found}')
            print(f'   ! No data available: {ap_position_no_data}')
            print(f'   ✗ API error: {ap_position_error}')
            
            # AP Position Update Statistics
            ap_update_attempted = sum(1 for r in results if r.get('AP Update Status'))
            ap_update_success = sum(1 for r in results if 'Success' in r.get('AP Update Status', ''))
            ap_update_timeout = sum(1 for r in results if r.get('AP Update Status') == 'Timeout')
            ap_update_failed = sum(1 for r in results if r.get('AP Update Status', '').startswith('Failed'))
            
            print(f'\n4. AP POSITION UPDATE:')
            print(f'   APs with position data: {ap_update_attempted}')
            print(f'   ✓ Successfully updated: {ap_update_success}')
            print(f'   ⏱ Timeout: {ap_update_timeout}')
            print(f'   ✗ Failed: {ap_update_failed}')
            
            # Overall Status
            fully_successful = sum(1 for r in results if 
                                  r.get('Get Device Status') == 'Success' and
                                  'Success' in r.get('Get Site Status', '') and
                                  'Success' in r.get('AP Update Status', ''))
            
            print(f'\n5. OVERALL:')
            print(f'   ✓ Fully completed (all steps): {fully_successful}/{total_devices}')
            print(f'   Success rate: {(fully_successful/total_devices*100):.1f}%' if total_devices > 0 else '   Success rate: N/A')
            
            print('='*80)
            
        return results
            
    except Exception as e:
        print(f'Error processing CSV file: {e}')
        import traceback
        traceback.print_exc()

def save_devices_with_uuids(results, original_fieldnames):
    if not results:
        return
    
    #timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    #filename = f'devices_with_uuids_{timestamp}.csv'
    filename = f'devices_with_result.csv'
    
    try:
        # Add new columns at the beginning
        new_fieldnames = ['Device UUID', 'Device IP', 'Current Device Location', 'Get Device Status', 
                         'New Floor ID', 'Get Site Status', 'Unassign Status', 'Unassign Task ID',
                         'Assign Status', 'Assign Task ID', 'AP Position', 'AP Radios', 
                         'AP Position Status', 'AP Update Status', 'AP Update Task ID'] + list(original_fieldnames)
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=new_fieldnames, extrasaction='ignore')
            writer.writeheader()
            
            for result in results:
                writer.writerow(result)
        
        print(f'\nUpdated CSV saved to: {filename}')
        print(f'New columns added: "Device UUID", "Device IP", "Current Device Location", "Get Device Status", "New Floor ID", "Get Site Status", "Unassign Status", "Unassign Task ID", "Assign Status", "Assign Task ID", "AP Position", "AP Radios", "AP Position Status", "AP Update Status", "AP Update Task ID"')
        
    except Exception as e:
        print(f'Error saving results: {e}')
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()
