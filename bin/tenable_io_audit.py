import os
import sys
import json
import requests
import dateutil.parser
from datetime import datetime, timedelta
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.modularinput import *

class Input(Script):
    MASK = "<encrypted>"
    APP = __file__.split(os.sep)[-3]

    def get_scheme(self):

        scheme = Scheme("Tenable.io Audit")
        scheme.description = ("Grab Audit data from the Tenable.io API")
        scheme.use_external_validation = False
        scheme.streaming_mode_xml = True
        scheme.use_single_instance = False

        scheme.add_argument(Argument(
            name="domain",
            title="Domain",
            data_type=Argument.data_type_string,
            required_on_create=False,
            required_on_edit=False
        ))
        scheme.add_argument(Argument(
            name="access_key",
            title="Access Key",
            data_type=Argument.data_type_string,
            required_on_create=True,
            required_on_edit=True
        ))
        scheme.add_argument(Argument(
            name="secret_key",
            title="Secret Key",
            data_type=Argument.data_type_string,
            required_on_create=True,
            required_on_edit=True
        ))
        return scheme

    def stream_events(self, inputs, ew):
        self.service.namespace['app'] = self.APP
        # Get Variables
        input_name, input_items = inputs.inputs.popitem()
        kind, name = input_name.split("://")
        checkpointfile = os.path.join(self._input_definition.metadata["checkpoint_dir"], name)
        base = 'https://'+input_items["domain"]+'/audit-log/v1/events'

        # Password Encryption / Decryption
        updates = {}
        for item in ["access_key","secret_key"]:
            stored_password = [x for x in self.service.storage_passwords if x.username == item and x.realm == name]
            if input_items[item] == self.MASK:
                if len(stored_password) != 1:
                    ew.log(EventWriter.ERROR,f"Encrypted {item} was not found for {input_name}, reconfigure its value.")
                    return
                input_items[item] = stored_password[0].content.clear_password
            else:
                if(stored_password):
                    ew.log(EventWriter.DEBUG,"Removing Current password")
                    self.service.storage_passwords.delete(username=item,realm=name)
                ew.log(EventWriter.DEBUG,"Storing password and updating Input")
                self.service.storage_passwords.create(input_items[item],item,name)
                updates[item] = self.MASK
        if(updates):
            self.service.inputs.__getitem__((name,kind)).update(**updates)

        headers = {
            'accept': 'application/json','content-type': 'application/json',
            'x-apikeys': f"accessKey={input_items['access_key']};secretKey={input_items['secret_key']}",
        }
        
        # Checkpoint
        try:
            start = int(open(checkpointfile, "r").read())
        except:
            ew.log(EventWriter.WARN,"No Checkpoint found, starting 89 days ago")
            start = int(time.time()) - 7689600

        startdate = datetime.fromtimestamp(start)
        startstring = datetime.strftime(startdate,"%Y-%m-%d")
        # Get the timestamp for the next midnight
        end = start
        nextday = start - (start%86400) + 86400
        # Dont let this value be in the future
        if(nextday > time.time()):
            nextday = start

        ew.log(EventWriter.INFO,f"Start is {start}, next checkpoint must be at least {nextday}, requesting from {startstring}")

        response = requests.get(base, headers=headers, params={'f':f"date.gt:{startstring}",'limit':'5000'})
        ew.log(EventWriter.DEBUG,response.url)
        count = 0
        if(response.ok):
            data = response.json()
            
            ew.log(EventWriter.DEBUG,data["pagination"])
            events = data['events']
            for event in events:
                timestamp = int(dateutil.parser.parse(event['received']).timestamp())
                if(timestamp > start):
                    end = max(end,timestamp)
                    count = count + 1
                    if "fields" in event:
                        fields = {}
                        for x in event["fields"]:
                            fields[x["key"]] = x["value"]
                        event["fields"] = fields

                    ew.write_event(Event(
                        time=timestamp,
                        host=input_items["domain"],
                        source="/audit-log/v1/events",
                        data=json.dumps(event, separators=(',', ':'))
                    ))
            ew.log(EventWriter.INFO,f"Wrote {count} new events from {len(events)} returned, covering {round((end-start)/86400,1)} days, next checkpoint is {end}")

            # Catch the API Limit running out
            if(end < nextday):
                ew.log(EventWriter.WARN,f"Some events on {startstring} will be lost as more than 5000 occured in a single day. Forcing checkpoint from {end} to {nextday} ({int((nextday-end)/60)} minutes lost).")
                end = nextday
        else:
            ew.log(EventWriter.ERROR,f"Request returned status {response.status_code}, {response.text}")
        ew.close()
        
        open(checkpointfile, "w").write(str(int(end)))

if __name__ == '__main__':
    exitcode = Input().run(sys.argv)
    sys.exit(exitcode)