import calendar, time

from icecream import ic
from zeek_sysmon import *
from data import *
from icecream import ic

import warnings  
warnings.filterwarnings("ignore") 

from argparse import ArgumentParser
import time
import pandas as pd

def queryLogsbyELK():
    data = Data()

    start_time = '2021-03-15' + 'T16:00:00.000' + '+08:00'
    end_time = '2021-03-15' + 'T16:05:00.000' + '+08:00'

    # query sysmon data
    #sysmon_data = data.elk.query('*weitung.winlog_sysmon*', start_time, end_time, [], ['winlog'])
    sysmon_data = data.elk.query('*win10_1511*', start_time, end_time, [], ['winlog'])
    
    # query zeek data
    zeek_conn_data = data.elk.query('logstash-sdn.zeek-conn*', start_time, end_time, [{'message':'192.168.1.117'}], [])
    zeek_dns_data = data.elk.query('logstash-sdn.zeek-dns*', start_time, end_time, [{'message':'192.168.1.117'}], [])
    # zeek_http_data = data.elk.query('logstash-sdn.zeek-http*', start_time, end_time, [], [])

    zeek_data = {'conn': zeek_conn_data, 'dns': zeek_dns_data}

    return sysmon_data, zeek_data

def queryLogsbyAPT29():
    print('querying')
    data = Data()
    
    # sysmon data
    sysmon_data = []
    sysmon_data += data.apt29.query('day1', 'sysmon')
    sysmon_data += data.apt29.query('day2', 'sysmon')
    
    # zeek conn data
    zeek_data = {'conn': [], 'dns': []}
    day1_logs = ['NASHUA', 'SCRANTON']
    day2_logs = ['NEWYORK', 'SCRANTON', 'UTICA-A']

    # day1
    for log in day1_logs:
        for log_type in zeek_data:
            file_name = f'{log}_{log_type}.log'
            zeek_data[log_type] += data.apt29.query('day1', 'zeek', file_name)
    # day2
    for log in day2_logs:
        for log_type in zeek_data:
            file_name = f'{log}_{log_type}.log'
            zeek_data[log_type] += data.apt29.query('day2', 'zeek', file_name)
    
    return sysmon_data, zeek_data

def preprocess(data, log_type):
    print(log_type, 'preprocessing...')
    if log_type == 'sysmon':
        return pd.json_normalize(data)

    if log_type == 'zeek':
        zeek_data = pd.DataFrame()

        for zeek_type in data:
            logs = pd.json_normalize(data[zeek_type])               
            logs['ts'] = pd.to_numeric(logs['ts'], errors='coerce') # change ts type
            logs = logs.rename(lambda x: f'{zeek_type}.{x}' if not x in ['uid'] else x, axis='columns')   
            zeek_data = logs if 'uid' not in zeek_data.columns else zeek_data.merge(logs, on='uid', how='outer')
        
        zeek_data['conn.ts'] = zeek_data['conn.ts'].fillna(0)
        return zeek_data

def convert(x):
    try:
        return x.astype(int)
    except:
        return x

def main():
    start_time = time.time()

    if args.action == 'query':    
        if args.dataset == 'elk':
            sysmon_data, zeek_data = queryLogsbyELK()
        elif args.dataset == 'apt29':
            sysmon_data, zeek_data = queryLogsbyAPT29()
        
        sysmon_data, zeek_data = preprocess(sysmon_data, 'sysmon'), preprocess(zeek_data, 'zeek')
        sysmon_data.to_csv('./query_data/sysmon.csv', index=False)
        zeek_data.to_csv('./query_data/zeek.csv', index=False)
        
        print('querying finished')
        
    if args.action == 'correlate': 
        sysmon_data = pd.read_csv('./query_data/sysmon.csv', low_memory=True).apply(convert)
        zeek_data = pd.read_csv('./query_data/zeek.csv', low_memory=True).apply(convert)
        zs = ZeekSysmon(sysmon_data, zeek_data)
        zeek_sysmon_data = zs.correlate()
        print('csv saving...')
        # zeek_sysmon_data.to_csv('./correlated_data/elk.csv')

    print(time.time() - start_time)


if __name__ == '__main__':
    parser = ArgumentParser(description = 'argument setting')
    parser.add_argument('-d', '--dataset', choices=['elk', 'apt29'], help='choose datasets', dest='dataset', default='elk')
    parser.add_argument('-a', '--action', choices=['query', 'correlate'], help='choose action', dest='action', default='query')
    args = parser.parse_args()

    main()