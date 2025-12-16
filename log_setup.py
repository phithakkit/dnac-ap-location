"""
DNAC Discovery Script.
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
"""

__author__ = "Phithakkit Phasuk"
__email__ = "phphasuk@cisco.com"
__version__ = "0.1.2"
__copyright__ = "Copyright (c) 2021 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.1"


import time
import logging.handlers
import logging

def log_setup(log_level, log_file, log_term=False):
    formatter = logging.Formatter(
        '%(asctime)s.%(msecs)d %(levelname)s process_id [%(process)d]: %(message)s',
        '%Y-%m-%d %H:%M:%S')
    formatter.converter = time.localtime
    logger = logging.getLogger()
    logger.setLevel(log_level)
    if log_file:
        file_handler = logging.handlers.RotatingFileHandler(log_file, maxBytes=2048*10000, backupCount=5)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    if log_term:
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)
