# Prerequisites:
# 1. Mailutils and Postfix installed on Linux machine
# 2. Postfix SMTP server configured
# 3. Suricata to be installed in default directories

import pandas as pd
import os
import re
from datetime import timedelta
import time


def send_email(body, header, timedate, objects):
    header = header[0].replace("(", "").replace(")", "")
    source = objects[0].split(':')
    dest = objects[1].split(':')

    body_details = list(body[0])
    message_log = body_details[1].replace("(", "").replace(")", "")

    command = f'echo "A new attack detected from the source address: {source[0]} at port {source[1]} and destination address: {dest[0]} at port {dest[1]}.\nTime of occurance: {timedate}.\nMessage details: {message_log}" | mail -s "Suricata detected a(n) \'{header}\' attack" -a "From: suricata@terrasystems.com" wee.kang@exchange.terra.systems'

    # Executing the mail command in the Linux command line
    os.system(command)
    print("Email alert sent: ", {command})


attacks = ["1000001", "1000002", "1000003", "1000009", "1000010", "1000011", "1000012", "1000013", "2000001", "2000002",
           "2000003"]


def check_log_file(filename):
    # simple animation
    animation = [" [ =     ] ", " [  =    ] ", " [   =   ] ", " [    =  ] ", " [     = ] "]
    idx = 0

    now = pd.to_datetime(pd.Timestamp.now())
    # Datetime to refresh memory of previous logs in the past 5 minutes
    log_expiry = now + pd.to_timedelta(5, unit='m')
    previous_logs = []

    with open(filename, "r") as f:
        current_position = f.seek(0, 2)
        while True:
            print(animation[idx % len(animation)], end="\r")
            idx += 1

            # Refresh log memory (so it will not spam)
            if now > log_expiry:
                log_expiry = now + pd.to_timedelta(5, unit='m')
                previous_logs = []
                print("Refreshed logs memory")

            f.seek(current_position)
            new_logs = f.read()

            # Split new logs into lines
            new_logs_list = [line.strip() for line in new_logs.split('\n') if line.strip()]
            for line in new_logs_list:
                event = pd.to_datetime(line[0:20])
                try:
                    meta_pattern = r'\[\*\*\] \[(.*?)\] (.+?) \[\*\*\]'
                    metadata = re.findall(meta_pattern, line)

                    classification_pattern = r'\[Classification: (.*?)\]'
                    classification = re.findall(classification_pattern, line)
                    # print(classification)

                    ip_port_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}:\d+\b'
                    ip_port_addresses = re.findall(ip_port_pattern, line)
                    # print(ip_port_addresses)

                    # Make list searchable
                    #previous_logs_set = set(previous_logs)
                    #print(line)
                    if re.findall(':[12]\d{6}:', line)[0].replace(':', '') in attacks and metadata[0] not in previous_logs:
                        print("New attack detected")
                        previous_logs.append(metadata[0])
                        send_email(metadata, classification, event, ip_port_addresses)
                    else:
                        pass
                except IndexError as ie:
                    pass

            # Get position of last line to start off the next loop
            current_position = f.tell()
            now = pd.to_datetime(pd.Timestamp.now())
            time.sleep(2)


check_log_file("/var/log/suricata/fast.log")
