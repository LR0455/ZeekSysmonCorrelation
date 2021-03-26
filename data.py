from elk import *
import config
import os
import warnings  
warnings.filterwarnings("ignore") 

import json

class Data:
    def __init__(self):
        self.elk = self.ELK()
        self.apt29 = self.APT29()

    class ELK:
        def __init__(self):
            self.data = None

        def query(self, index, start_time, end_time, condition, columns):
            print("elk logs querying ...")
            es = ElasticSearch(config.es.host, config.es.cred)
            
            es.index(index)
            es.time(start_time, end_time)
            es.column(columns)
            es.must_reg(condition)
            
            return es.search(clear=True)
            
    class APT29:
        def __init__(self):
            self.day1_folder = './dataset/apt29/datasets/day1/'
            self.day2_folder = './dataset/apt29/datasets/day2/'
            self.zeek_folder = 'zeek/individual_zeek_logs/'
            self.sysmon_file = 'sysmon.json'

            self.day1_zeek_conn_data = []
            self.day2_zeek_conn_data = []
            
        def setargs(self, day1_folder, day2_folder, zeek_folder, sysmon_file):
            self.day1_folder = day1_folder
            self.day2_folder = day2_folder
            self.zeek_folder = zeek_folder
            self.sysmon_file = sysmon_file

        def path(self, day, source, file_name = []):
            if day == 'day1':
                if source == 'sysmon':
                    return os.path.join(self.day1_folder, self.sysmon_file)
                if source == 'zeek':
                    return os.path.join(self.day1_folder, self.zeek_folder, file_name)
            if day == 'day2':
                if source == 'sysmon':
                    return os.path.join(self.day2_folder, self.sysmon_file)
                if source == 'zeek':
                    return os.path.join(self.day2_folder, self.zeek_folder, file_name)
            return None

        def query(self, day, source, file_name = []):
            self.source = source
            print(self.path(day, source, file_name))
            data = self.openFile(self.path(day, source, file_name))
            data = list(map(self.preprocess, data))
            return list(filter(lambda x: x is not None, data))

        def preprocess(self, log):
            log = json.loads(log)
            if self.source == 'zeek':
                log['message'] = ''
                for val in log.values():
                    log['message'] += str(val) + ' '
                return log
            # transform apt29 log to elk log format
            elk_log = {'winlog':{'event_data': {}, 'event_id': log['EventID']}}
            
            # filter non sysmon log
            if elk_log['winlog']['event_id'] > 25:
                return None
            
            log['Message'] = log['Message'].split('\r\n')
            
            for log_msg in log['Message']:
                log_msg = log_msg.split(': ')
                key, val = log_msg[0], None if len(log_msg) == 1 else log_msg[1]
                elk_log['winlog']['event_data'][key] = val
            
            # guid name is not same with elk
            winlog = elk_log['winlog']
            
            if 'ProcessGuid' in winlog['event_data']:
                return elk_log
            elif 'ProcessGUID' in winlog['event_data']:
                winlog['event_data']['ProcessGuid'] = winlog['event_data']['ProcessGUID']
                return elk_log
            elif 'SourceProcessGUID' in winlog['event_data']:
                winlog['event_data']['ProcessGuid'] = winlog['event_data']['SourceProcessGUID']
                return elk_log
            
            return None
            
   
        def openFile(self, file):
            with open(file, 'r', encoding='utf-8') as file:
                return file.readlines()


