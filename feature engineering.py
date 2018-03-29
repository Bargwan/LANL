#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import numpy as np
import pandas as pd

dns_headings = ['time','source_computer','computer_resolved']
dns = pd.read_csv('F:\\capstone\\dns.txt\\dns.txt',  names=dns_headings, sep=',')
dns.head()
dns_feature=dns.sort_values(by=['time','source_computer','computer_resolved'])
dns_feature['time_shift'] = dns_feature.groupby('source_computer')['time'].shift()
dns_feature['interval'] = dns_feature['time']-dns_feature['time_shift'] 
dns_feature['row_num'] = dns_feature.index
###To saving time, using top 5000 records
#dns_feature_test = dns_feature.head(5000)
#dns_feature_test.head()
###########################################

dns_feature_test=dns_feature

def access_time_interval(df):
    time_interval = []
    max_freq =  df['time'].value_counts().values[0]
    time_interval.append(df['interval'].min() )
    time_interval.append(df['interval'].max() )
    time_interval.append(df['interval'].mean() )
    time_interval.append(max_freq)    
    computer_resolved_distict = len(set(list(df['computer_resolved'])))    
    time_interval.append(computer_resolved_distict)
    return time_interval

def extract_forward(source_computer,computer_resolved,window_size,extract_type ='time_interval',timestamp=None,index_num=None):
    if extract_type == 'time_interval':
        ##indices related to time intervals
        #timestamp gap=100, also can be identified by window_size
        ##min/max/avg interval of events by source_computer 
        print (timestamp,source_computer)
        timestamp_1 =timestamp 
        start_time = timestamp_1 - window_size
        df_extract=dns_feature_test[(dns_feature_test['time'] >= start_time)  & 
        (dns_feature_test['time']<timestamp_1) & (dns_feature_test['source_computer']==source_computer) & 
        (dns_feature_test['interval'].notnull())]
        print (df_extract.shape[0])
        if df_extract.shape[0] <= 0:
            return 0,0,0,0,0
        else:
            time_interval_index= access_time_interval(df_extract)
            #re = pd.Series([time_interval_index[0],time_interval_index[1],time_interval_index[2],time_interval_index[3],time_interval_index[4] ])
            return pd.Series([time_interval_index[0],time_interval_index[1],time_interval_index[2],time_interval_index[3],time_interval_index[4] ])
           
                        
    if extract_type == 'computer_resolved_counts':
        print (computer_resolved)
        #min/max/avg interval of events by computer_resolved
        computer_resolved_counts = 0
        start_num = index_num - window_size
        if start_num >= 0:
            df_extract = dns_feature_test[['computer_resolved']][start_num:index_num-1]
            df_extract['counts'] = 0
            df_extract['counts'] = df_extract[df_extract['computer_resolved']==computer_resolved]
            df_extract['counts'].ix[df_extract['computer_resolved']==computer_resolved] = 1
            computer_resolved_counts=df_extract['counts'].sum()
        return computer_resolved_counts
    
    if extract_type == 'computer_resolved_time':
        ##过去100时间单位，与computer_resolved相同的访问次数，和占比
        computer_resolved_time_list = []
        timestamp_1 = timestamp
        start_time = timestamp_1 - window_size
        df_extract=dns_feature_test[(dns_feature_test['time'] >= start_time)  & 
        (dns_feature_test['time']<timestamp_1)][['computer_resolved']]
        print (df_extract.shape)
        if df_extract.shape[0] <= 0:
            computer_resolved_time_list = [0.0,0.0]
        else:
            df_extract['counts'] =0.0
            df_extract['counts'].ix[df_extract['computer_resolved']==computer_resolved] = 1
            computer_resolved_counts=df_extract['counts'].sum()
            ratio = computer_resolved_counts/df_extract.shape[0]
            computer_resolved_time_list.append(computer_resolved_counts)
            computer_resolved_time_list.append(ratio)
        return pd.Series([computer_resolved_time_list[0],computer_resolved_time_list[1]])

dns_feature_test['interval_min'],dns_feature_test['interval_max'],dns_feature_test['interval_mean'],dns_feature_test['max_freq'],dns_feature_test['computer_resolved_distict'] = dns_feature_test.apply(lambda x: extract_forward(x['source_computer'],computer_resolved=None,window_size=100,extract_type ='time_interval',timestamp=x['time'],index_num=None),axis=1)

##features by source_computer
#dns_feature_test[['interval_min','interval_max','interval_mean','max_freq','computer_resolved_distict']] = 
df1=dns_feature_test.apply(lambda x: extract_forward(x['source_computer'],computer_resolved=None,window_size=100,extract_type ='time_interval',timestamp=x['time'],index_num=None),axis=1)

##features by computer_resolved
dns_feature_test['computer_resolved_counts']=dns_feature_test.apply(lambda x: extract_forward(source_computer=None,computer_resolved=x['computer_resolved'],window_size=100,extract_type ='computer_resolved_counts',timestamp=None,index_num=x['row_num']),axis=1)
##features by computer_resolved
#dns_feature_test[['computer_resolved_counts','ratio']]=
df2=dns_feature_test.apply(lambda x: extract_forward(source_computer=None,computer_resolved=x['computer_resolved'],window_size=100,extract_type ='computer_resolved_time',timestamp=x['time'],index_num=None),axis=1)

c = pd.DataFrame([df1,df2])
c.columns = ['interval_min','interval_max','interval_mean','max_freq','computer_resolved_distict','computer_resolved_counts','ratio']
dns_feature_test= pd.concat([dns_feature_test,c])

dns_feature_test.to_csv("dns_feature_test.csv")

dns_feature_test.columns
dns_feature_test.tail()
dns_feature_test.shape


