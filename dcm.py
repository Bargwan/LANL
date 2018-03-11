"""DCM (DNS Clustering Module) was designed to perform cluster analysis on
the Los Alamos National Laboratory DNS data from the cyber security dataset
(available at https://csr.lanl.gov/data/cyber1/). It contains the option of
performing a more general analysis on sliding time based windows on the top n
resolved computers.

More features, such as different clustering methods, will likely be added in the
immediate future."""

import pandas as pd
import scipy.stats
from sklearn.cluster import KMeans


def GetTopn(data,n=50):
    """Returns a list of the names of the highest resolved computers."""
    data=data.computer_resolved.groupby(data.computer_resolved).count()
    data=data.sort_values(ascending=False)
    highest_resolved_computers=data.index[0:n]
    
    return highest_resolved_computers


def GetConnectionStats(group, extended_features=False):
    """Calculate the statistics of a pandas df grouped by resolved computer."""
    num_connections=group.time.value_counts()
    
    if extended_features:
    
        connection_stats={'minimum': num_connections.min(), 
                        'maximum': num_connections.max(), 
                        'count': num_connections.count(),
                        'mean': num_connections.mean(),
                        'std': num_connections.std(),
                        'skew': scipy.stats.skew(num_connections),
                        'kurtosis': scipy.stats.kurtosis(num_connections)}
    else:
        
        connection_stats={'count': num_connections.count()}
                        
    return connection_stats
    
    
def DNSDFToStatsDF(dns_df, n=50):
    """Calculate statistics of resolved computers in a DNS-like dataframe.
    
    Takes a dataframe in the same format as the original DNS data.
    Various statistical parameters are then calculated for the top n resolved
    computers. These statistics are then returned with the corresponding computer
    resolved as a feature."""
    highest_resolved_computers=GetTopn(dns_df,n)
    dns_df=dns_df.loc[dns_df.computer_resolved.isin(highest_resolved_computers)]
    
    new_df=dns_df.groupby(dns_df.computer_resolved).apply(GetConnectionStats)
    new_df=pd.DataFrame(new_df)
    new_df.reset_index(inplace=True)

    stats=new_df[0].tolist()

    stats_df=pd.DataFrame(stats)

    stats_df["computer_resolved"]=new_df.computer_resolved
    
    return stats_df
    
    
def ClusterAnalysis(data, k=3):
    """Cluster using k-means. Different methods may be added later."""
    computer_resolved=data.computer_resolved
    data.drop(["computer_resolved"], axis=1, inplace=True)
    
    data=Normalize(data)
    
    Clustering=KMeans(k).fit(data)
    
    return computer_resolved, Clustering
    
    
def Normalize(data):
    """Normalize the data."""
    mean = data.mean(axis=0)
    std = data.std(axis=0)
    std[std<0.01]=1
    
    data=data-mean 
    data=data/(std)
    
    return data
    
    
def SlidingWindow(data, analysis_function=ClusterAnalysis, window_size=5011199,
                    stride=1, n=50):
    """Applies analysis_function to sliding windows across the data.
    
    Takes in the DNS dataframe and then applies analysis_function to sliding
    windows defined by window_size and stride. These parameters can be altered
    to result in smaller or larger windows with greater or lesser overlap.
    analysis_function may be anything that operates in the DNS dataframe.
    
    The return value is a dictionary indexed by sliding window number containing
    the results of analysis_function."""
    start_time=0
    end_time=window_size
    max_time=data.time.max()
    
    results={}
    window_number=1
    is_final_window=False
    
    while is_final_window==False:
        
        current_data=data[(data.time>=start_time) & (data.time<end_time)]
        
        highest_resolved_computers=GetTopn(current_data, n)
        highest_resolved_dns=current_data.loc[current_data.computer_resolved.isin(highest_resolved_computers)]

        highest_resolved_stats=DNSDFToStatsDF(highest_resolved_dns)
        
        results["Window_"+str(window_number)]=analysis_function(highest_resolved_stats)
        
        window_number+=1
        
        start_time+=stride
        end_time+=stride
        
        if end_time>=max_time:
            
            is_final_window=True
       
    return results 