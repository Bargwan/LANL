import pandas as pd
import numpy as np
import os

path="F:\\Masters degree\\Capstone Project"

os.chdir(path+"\\data")

dns_headings = ['time','source_computer','computer_resolved']
dns = pd.read_csv("dns.txt", sep=',', header=None, names=dns_headings)

redteam_auth_headings=[ "time", "user@domain","source_computer", "destination_computer"]
redteam_auth = pd.read_csv('redteam.txt', sep=',', header=None, 
                            names=redteam_auth_headings)
                  
# Use 0 for non-malicious and 1 for malicious                                      
dns["malicious"]=0
        
# This attempts to match red team events to DNS queries. This is optimised using
# the temporal order of the data.                    
def AssignRedTeamEvents(dns_df, redteam_df):
    
    redteam_rows=redteam_df.shape[0]
    dns_rows=dns.shape[0]
    
    start=99885
    add_start=0
    
    for i in range(0,redteam_rows):
        
        time=redteam_df.loc[i].time
        
        start+=add_start
        
        terminate_if_no_match=False
        
        for j in range(start,dns_rows):
            
            if ((redteam_df.loc[i].source_computer==dns_df.loc[j].source_computer) and 
            (redteam_df.loc[i].destination_computer==dns_df.loc[j].computer_resolved) and
            ((time==dns_df.loc[j].time) or (time+1==dns_df.loc[j].time))):
            
                dns_df.loc[j].malicious=1
                print("SUCCESS!")
                terminate_if_no_match=True
                
            elif terminate_if_no_match==False:
                
                add_start+=1
                
            if (dns_df.loc[j+1].time>time+1):
                
                break
                
AssignRedTeamEvents(dns, redteam_auth)

#new_df = pd.merge(dns, redteam_auth,  how='left', left_on=['time','source_computer','computer_resolved'], right_on = ['time','source_computer','destination_computer'])

# This does something similar to the above, but it does a comprehensive search.
# It takes a LONG time!
def IsMatch(dns, redteam):
    
    redteam_rows=redteam.shape[0]
    
    for i in range(0, redteam_rows):
    
        result=dns.loc[(dns['source_computer']==redteam.loc[i].source_computer) & (dns['time']==redteam.loc[i].time) & (dns['computer_resolved']==redteam.loc[i].destination_computer)]
        
        if result.empty!=True:
            
            print("SUCCESS!")
            
IsMatch(dns, redteam_auth)