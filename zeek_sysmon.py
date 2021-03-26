import json
import calendar, time
from icecream import ic
from datetime import datetime
# import pandas as pd
import pandas as pd
import time
import threading

class ZeekSysmon:
    def __init__(self, sysmon_raw_data, zeek_raw_data):
        sysmon_thread = threading.Thread(target=self._sysmonInit, args=(sysmon_raw_data, ))
        zeek_thread = threading.Thread(target=self._zeekInit, args=(zeek_raw_data, ))

        sysmon_thread.start()
        zeek_thread.start()

        sysmon_thread.join()
        zeek_thread.join()
        
    
    def _sysmonInit(self, sysmon_raw_data):
        # sysmon initial
        self.sysmon_raw_data = pd.json_normalize(sysmon_raw_data)
        self.sysmon_raw_data = self.sysmon_raw_data.fillna('')

        # get same prefix columns
        #print(self.sysmon_raw_data.loc[:, lambda x: list(map(lambda y: y.startswith('winlog.'), x))])
        
        self.sysmon = self.sysmon(self)
        self.sysmon_data = self.sysmon.removeInvaildID() 
        self.sysmon_data['winlog.event_data.UtcTime'] = self.sysmon_data['winlog.event_data.UtcTime'].apply(self.utcTosec)
        self.correlated_sysmon_data, self.sysmon_parent_process_guid, self.min_time_by_guid, self.max_time_by_guid = self.sysmon.correlateProcessGuid()
        self.sysmon_network_data = self.sysmon.getLogsbyEventID([3])

    def _zeekInit(self, zeek_raw_data):
        # zeek initial
        self.zeek_raw_data = zeek_raw_data
        self.zeek = self.zeek(self)
        self.correlated_zeek_data = self.zeek.correlateUid()

    class sysmon:
        def __init__(self, super_self):
            self.super = super_self
        
        # The system time was changed. => event_id=4616
        def removeInvaildID(self):
            print("sysmon invalid id removing ...")
            return self.super.sysmon_raw_data.query('`winlog.event_id` <= 25')

        # {'guid': [sysmon_event1, sysmon_event2, ...]}
        def correlateProcessGuid(self):
            print("sysmon process guid correlating ...")
            
            process_guid_group = self.super.sysmon_data.groupby('winlog.event_data.ProcessGuid')
            min_time_by_guid = process_guid_group['winlog.event_data.UtcTime'].min().to_dict()
            max_time_by_guid = process_guid_group['winlog.event_data.UtcTime'].max().to_dict()
            sysmon_parent_process_guid = process_guid_group['winlog.event_data.ParentProcessGuid'].max().to_dict()
                
            return process_guid_group, sysmon_parent_process_guid, min_time_by_guid, max_time_by_guid
            
        # search specific event id of sysymon logs
        def getLogsbyEventID(self, event_ids):
            print("sysmon logs by event id getting ...")
            return self.super.sysmon_data.query(f'`winlog.event_id` in {event_ids}').reset_index()

        def getLogsbyGuid(self, guids):
            #print("sysmon logs by guid getting ...")
            related_logs = [self.super.correlated_sysmon_data.get_group(guid) for guid in guids if guid in self.super.correlated_sysmon_data.size()]
            return pd.concat(related_logs)

        # search 
        def getRelatedGuid(self, guid):
            #print("sysmon related guid getting ...")
            related_guid = []
            while guid:
                related_guid.append(guid)
                if guid not in self.super.sysmon_parent_process_guid:
                    break
                guid = self.super.sysmon_parent_process_guid[guid]
            return related_guid
        
        def getMinMaxTime(self, related_guid):
            #print("sysmon min max time getting ...")
            min_time = 1e9
            max_time = 0

            for guid in related_guid:
                if guid in self.super.min_time_by_guid:
                    min_time = min(min_time, self.super.min_time_by_guid[guid])
                if guid in self.super.max_time_by_guid:
                    max_time = max(max_time, self.super.max_time_by_guid[guid])
            
            return min_time, max_time

    class zeek:
        def __init__(self, super_self):
            self.super = super_self

        def correlateUid(self): 
            print("zeek uid correlating ...")

            zeek_data = pd.DataFrame()
            for zeek_type in self.super.zeek_raw_data:
                logs = pd.json_normalize(self.super.zeek_raw_data[zeek_type])               
                logs['ts'] = pd.to_numeric(logs['ts'], errors='coerce') # change ts type
                logs = logs.rename(lambda x: f'{zeek_type}.{x}' if not x in ['uid'] else x, axis='columns')   
                zeek_data = logs if 'uid' not in zeek_data.columns else zeek_data.merge(logs, on='uid', how='outer')
            
            zeek_data['conn.ts'] = zeek_data['conn.ts'].fillna(0)
            return zeek_data.fillna('')
            
        def getRelatedLogs(self, conditions, start_time, end_time):
            #print("zeek related uid getting ...")
            related_zeek_data = self.super.correlated_zeek_data[self.super.correlated_zeek_data['conn.ts'].between(start_time, end_time)]
            query = ' and '.join(map(lambda cond: f'`{cond[0]}` == "{cond[1]}"', conditions.items()))
            related_zeek_data = related_zeek_data.query(query)
            
            return related_zeek_data

    def utcTosec(self, utc):
        return calendar.timegm(time.strptime(utc, '%Y-%m-%d %H:%M:%S.%f'))

    def secToutc(self, ts):
        return datetime.fromtimestamp(ts)

    def correlate(self):
        print("zeek and sysmon correlating ...")
        
        group_id = 1
        # improve speed
        self.corr_data = [pd.DataFrame()] * (len(self.sysmon_network_data)+1)
        thread = []
        for idx, log in self.sysmon_network_data.iterrows():
            t = threading.Thread(target=self._correlate, args=(log, group_id, ))
            group_id += 1
            thread.append(t)
            t.start()
        
        for t in thread:
            t.join()    
        
        self.correlated_data = pd.concat(self.corr_data)
        self.correlated_data = self.correlated_data.reset_index()
        self.correlated_data = self.correlated_data.fillna('')
        
        print(self.correlated_data)
        
        return self.correlated_data
        

    def _correlate(self, network_log, group_id = 0):
        
        src_ip, src_port = network_log['winlog.event_data.SourceIp'], network_log['winlog.event_data.SourcePort']
        dst_ip, dst_port = network_log['winlog.event_data.DestinationIp'], network_log['winlog.event_data.DestinationPort']
        protocol = network_log['winlog.event_data.Protocol']

        process_guid = network_log['winlog.event_data.ProcessGuid']
        related_guid = self.sysmon.getRelatedGuid(process_guid)
        min_time, max_time = self.sysmon.getMinMaxTime(related_guid)
        
        related_sysmon_data = self.sysmon.getLogsbyGuid(related_guid)   
        related_zeek_data = self.zeek.getRelatedLogs({'conn.id_orig_h': src_ip, 'conn.id_orig_p': src_port, 'conn.id_resp_h': dst_ip, 'conn.id_resp_p': dst_port, 'conn.proto': protocol}, min_time, max_time)
        
        if len(related_zeek_data):
            related_sysmon_data.insert(loc = 0, column = 'group_id', value = group_id)
            related_sysmon_data.insert(loc = 0, column = 'log_type', value = 'sysmon')

            related_zeek_data.insert(loc = 0, column = 'group_id', value = group_id)
            related_zeek_data.insert(loc = 0, column = 'log_type', value = 'zeek')
            
            self.corr_data[group_id] = related_sysmon_data
            self.corr_data[group_id] = self.corr_data[group_id].append(related_zeek_data)
        
        