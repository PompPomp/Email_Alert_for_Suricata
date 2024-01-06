import pandas as pd
import os
import re
import time

def send_email(body, header, timedate):
    header = header[0].replace("(", "").replace(")", "")
    
    body_details = list(body[0])
    message_log = body_details[1].replace("(", "").replace(")", "")
    
    command = f'echo "A new attack detected at {timedate}: {message_log}" | mail -s "Suricata detected a {header} attack" -a "From: suricata@terrasystems.com" jasonleeweekang@gmail.com'
    # Executing the mail command in the Linux command line
    os.system(command)
    print("Email alert sent")

attacks=["1000001"]

def check_log_file(filename):
    with open(filename, "r") as f:
        
        now = pd.to_datetime(pd.Timestamp.now())
        time.sleep(5)
        for line in f:
            event = pd.to_datetime(line[0:20])
            try: 
                meta_pattern = r'\[\*\*\] \[(.*?)\] (.+?) \[\*\*\]'
                metadata = re.findall(meta_pattern, line)
                #print(metadata)

                classification_pattern = r'\[Classification: (.*?)\]'
                classification = re.findall(classification_pattern, line)
                #print(classification)

                if re.findall(':1\d+:', line)[0].replace(':', '') in attacks and event < now:
                    send_email(metadata, classification, event)
                    print("Email sent")
                    break
                else:
                    pass
            except IndexError as ie:
                print(ie)

while True:
    check_log_file("./fast2.log")




