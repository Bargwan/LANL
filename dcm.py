"""DCM (DNS Clustering Module) was designed to perform cluster analysis on the 
Los Alamos National Laboratory DNS data from the cyber security dataset
(available at https://csr.lanl.gov/data/cyber1/). The clustering is based on the 
number of connections a computer receives within a given timeframe along with 
associated statistical features.

This module also contains the option of performing a more general analysis using 
sliding time based windows on the top n resolved computers.

More features, such as different clustering methods, will likely be added in the
immediate future."""

import pandas as pd
import numpy as np
import scipy.stats
from sklearn.cluster import KMeans
import matplotlib as mpl
import matplotlib.pyplot as plt
from matplotlib import colors
from matplotlib import pyplot


def GetTopn(data,n=50):
    """Returns a list of the names of the highest resolved computers."""
    data=data.computer_resolved.groupby(data.computer_resolved).count()
    data=data.sort_values(ascending=False)
    highest_resolved_computers=data.index[0:n]
    
    return highest_resolved_computers


def GetConnectionStats(group, extended_features=False):
    """Calculate the connection statistics of a pandas df grouped by resolved 
    computer."""
    num_connections=group.time.value_counts()
    
    if extended_features:
    
        connection_stats={'minimum': num_connections.min(), 
                        'maximum': num_connections.max(), 
                        'count': num_connections.count(),
                        'mean': num_connections.mean(),
                        'skew': scipy.stats.skew(num_connections),
                        'kurtosis': scipy.stats.kurtosis(num_connections)}
    else:
        
        connection_stats={'count': num_connections.count()}
                        
    return connection_stats
    
    
def DNSDFToStatsDF(dns_df, n=50, use_extended_features=False):
    """Calculate the connection statistics of resolved computers in a DNS-like 
    dataframe.
    
    Takes a dataframe in the same format as the original DNS data.
    Various statistical parameters are then calculated for the top n resolved
    computers. These statistics are then returned with the corresponding computer
    resolved as a feature."""
    highest_resolved_computers=GetTopn(dns_df,n)
    dns_df=dns_df.loc[dns_df.computer_resolved.isin(highest_resolved_computers)]
    
    new_df=dns_df.groupby(dns_df.computer_resolved).apply(GetConnectionStats, 
                                            extended_features=use_extended_features)
    new_df=pd.DataFrame(new_df) 
    
    
    new_df.reset_index(inplace=True)

    stats=new_df[0].tolist()

    stats_df=pd.DataFrame(stats)

    stats_df["computer_resolved"]=new_df.computer_resolved
    stats_df=stats_df.sort_values(by="count",ascending=False)
    
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
                    stride=1, n=50, use_extended_features=False):
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

        highest_resolved_stats=DNSDFToStatsDF(highest_resolved_dns, use_extended_features=use_extended_features)
        
        results["Window_"+str(window_number)]=analysis_function(highest_resolved_stats)
        
        window_number+=1
        
        start_time+=stride
        end_time+=stride
        
        if end_time>=max_time:
            
            is_final_window=True
       
    return results 
    
def OrderClustByConnections(cluster_centers, labels):
    """Replaces the cluster number with the rank."""
    cluster_centers=pd.DataFrame(cluster_centers)       
    cluster_total_connections=cluster_centers.loc[:,0]
        
    seq = sorted(cluster_total_connections)
    index = [seq.index(v) for v in cluster_total_connections]
        
    new_labels=list(range(0,len(labels)))
        
    for i in range(0, len(labels)):
            
        j=labels[i]
        new_labels[i]=index[j]
            
    return new_labels
    

def ProcessResults(results_dict):
    """Makes cluster labels consistent among entries in the results dict."""
    keys=results_dict.keys()
    
    for key in keys:
        
        computers, results=results_dict[key]
        cluster_centers=results.cluster_centers_
        labels=results.labels_
        
        new_labels=OrderClustByConnections(cluster_centers, labels)
        results_dict[key][1].labels_=new_labels
    
    return results_dict
            
def TrackClusterMembership(results_dict):
    """Produces a dataframe of cluster membership over the time windows."""
    # Get list of all computers in the dict
    unique_computers=[]
    
    for key, value in results_dict.items():
        
        computers, results=value
        computers=list(computers)
        unique_computers+=computers
        
    num_windows=len(results_dict)+1
    
    key = list(results_dict.keys())
    
    computers, results=results_dict[key[0]]
    
    clusters=results.cluster_centers_
    
    num_clusters=np.shape(clusters)[0]
    
    windows=[]
    
    for i in range(1, num_windows):
        
        windows.append("window_"+str(i))
        
    cols=["computer_resolved"]+windows
    
    num_unique_comp=len(unique_computers)
    
    membership_df=pd.DataFrame(index=range(0,num_unique_comp), columns=cols)
    
    num_cols=len(cols)
    
    for i in range(0, num_unique_comp):
        
        computer=unique_computers[i]
            
        membership_df.iloc[i,0]=computer
    
        for j in range(1, num_cols):
            
            window='Window_'+str(j)
            
            computers,results=results_dict[window]
            
            computers=list(computers)
            
            if computer in computers:
                
                k=computers.index(computer)
                
                cluster=results.labels_[k]
                
                membership_df.iloc[i,j]=cluster
              
            else:
                
                membership_df.iloc[i,j]=num_clusters-1
                
    return membership_df
    
def PlotClusterChanges(membership_df, colors=['white','orange','red']):
    
    new_array=[]

    # Filter out static desktops
    for i in range(0,np.shape(membership_df)[0]):
        
        if sum(list(membership_df.iloc[i,1:]))>0:
            
            test=membership_df.iloc[i,1:]
            
            new_array.append(list(test))    

    zvals = np.array(new_array)
    zvals=zvals.astype('float64')
    zvals_rows=np.shape(zvals)[0]
    zvals=np.repeat(zvals,20).reshape(zvals_rows,-1)
    #zvals=np.repeat(zvals,9, axis=0).reshape(zvals_rows*5,-1)
    
    # make a color map of fixed colors
    cmap = mpl.colors.ListedColormap(colors)
    num_clusters=len(np.unique(zvals))
    
    bounds=[]
    
    for i in range(0, num_clusters+1):
        
        bounds.append(-0.5+i)
    
    norm = mpl.colors.BoundaryNorm(bounds, cmap.N)
    
    # tell imshow about color map so that only set colors are used
    img = pyplot.imshow(zvals,interpolation='nearest',
                        cmap = cmap,norm=norm)
    
    # make a color bar
    graph=pyplot.colorbar(img,cmap=cmap,
                    norm=norm,boundaries=bounds,ticks=[0,1,2])
    graph.ax.set_title("Cluster membership of highest resolved computers over time")
    graph.ax.set_ylabel("Computer resolved")
    graph.ax.set_xlabel("Time window")
    graph.ax.set_label("Cluster")
    
    pyplot.show()
    
    return
    
    
def PlotClusterChanges2(membership_df):
    
    new_array=[]

    # Filter out static desktops
    for i in range(0,np.shape(membership_df)[0]):
        
        if sum(list(membership_df.iloc[i,1:]))>0:
            
            test=membership_df.iloc[i,1:]
            
            new_array.append(list(test))    

    data = new_array
    
    rows=np.shape(data)[0]
    columns=np.shape(data)[1]

    # create discrete colormap
    cmap = colors.ListedColormap(['red', 'blue', 'green'])
    bounds = [-0.5,0.5,1.5,2.5]
    norm = colors.BoundaryNorm(bounds, cmap.N)

    fig, ax = plt.subplots()
    ax.imshow(data, cmap=cmap, norm=norm)

    # draw gridlines
    ax.grid(which='major', axis='both', linestyle='-', color='k', linewidth=2)
    ax.set_xticks(np.arange(0, columns, 1));
    ax.set_yticks(np.arange(0, rows, 1));

    plt.show()
    
    return