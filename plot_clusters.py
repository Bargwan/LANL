# -*- coding: utf-8 -*-
"""
Based on example code here: 

https://stackoverflow.com/questions/36227475/heatmap-like-plot-but-for-categorical-variables-in-seaborn
"""

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns


import matplotlib.patches as mpatches

def clustWin(df,width=18,height=8): 
    # create dictionary with value to integer mappings
    value_to_int = {value: i for i, value in enumerate(sorted(pd.unique(df.values.ravel())))}
    f, ax = plt.subplots()
    f.set_size_inches(width,height)
    hm = sns.heatmap(df.replace(value_to_int),
                     linewidths=1, linecolor='black',
                     cmap="jet", 
                     ax=ax, 
                     cbar=False)
    hm.set_xlabel('Window')
    hm.set_ylabel('Computer')
    # add legend
    box = ax.get_position()
    ax.set_position([box.x0, box.y0, box.width * 0.7, box.height])
    legend_ax = f.add_axes([.7, .5, 1, .1])
    legend_ax.axis('off')
    # reconstruct color map
    colors = plt.cm.jet(np.linspace(0, 1, len(value_to_int)))
    # add color map to legend
    patches = [mpatches.Patch(facecolor=c, edgecolor=c) for c in colors]
    legend = legend_ax.legend(patches,
        sorted(value_to_int.keys()),
        handlelength=0.8, loc='lower left')
    for t in legend.get_texts():
        t.set_ha("left")


