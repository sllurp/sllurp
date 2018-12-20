from __future__ import print_function
import dash
import dash_core_components as dcc
import dash_html_components as html
import json
import time
import plotly.graph_objs as go
import numpy as np
from dash.dependencies import  Event, Output,Input
import plotly
import threading
import requests
tags = {}
ip = ""
jobID = ""
itemsenseIP = "" 
epc = []
x_locations = []
y_locations = []


getCurentTagsItemsense(itemsenseIP,jobID){
    while(true):
        lock.acquire()
        r = requests.get('http://' + itemsenseIP + '' + jobID)
        jsonResults = r.json()
        items = jsonResults.get("items")
        tags.clear()
        epc.clear()
        x_locations.clear()
        y_location.clear()
        for item in items:
            epc.insert(item.get('epc'))
            x_locations.insert(item.get('xLocation'))
            y_location.insert(item.get('yLocation'))
            tag = {'epc': item.get('epc'), 'x' : item.get('xLocation'), 'y' : item.get('yLocation')}
            tags.insert(tag)
        lock.release()
        time.sleep(2)
}

app.layout = html.Div(
    html.Div([
        #dcc.Graph(id='live-update-graph-scatter',animate=True),
        dcc.Graph(id='live-update-graph'),
        dcc.Interval(
            id='interval-component',
            interval=1*1000,
             n_intervals=0
        )
    ])
)

@app.callback(Output('live-update-graph', 'figure'),
              [Input('interval-component', 'n_intervals')])
def update_graph_live(n):
    # Create the graph with subplots
    # fig = plotly.tools.make_subplots(rows=2, cols=1, vertical_spacing=0.2)
    # fig['layout']['margin'] = {
    #     'l': 10, 'r': 10, 'b': 10, 't': 10
    # }
    # fig['layout']['legend'] = {'x': 0, 'y': 1, 'xanchor': 'left'}
    millis = int(round(time.time() * 1000000))

    lock.acquire()
   
    trace_tags = go.Scatter(
        x=x_locations,
        y=y_locations,
        text=epc,
        mode='markers',
        hoverinfo = 'x+y+text',
        marker=dict(
            size = 15,
            color = colors,
            opacity = 0.7,
            
        )
        
    ) 

    # trace_zone = go.Scatter(
    #     x=x_locations,
    #     y=y_locations,
    #     text=epc,
    #     mode='markers',
    #     hoverinfo = 'x+y+text',
    #     marker=dict(
    #         size = 15,
    #         color = colors,
    #         opacity = 0.7,
            
    #     )
    # )
    
    lock.release()
    data = [trace_tags]
    layout = go.Layout(autosize=True,title='Tag Location', 
        xaxis=dict(range=[-250, 250],
        title='X Distance cm',
        tick0=0,
        dtick=25,
        ticklen=8,
        tickwidth=4,
        tickcolor='#000'
        ),
        yaxis=dict(range=[-250, 250],
        title='Y Distance cm',
        tick0=0,
        dtick=50,
        ticklen=8,
        tickwidth=4,
        tickcolor='#000'
        )
    )

    return go.Figure(data=data,layout=layout)

    if __name__ == '__main__':

    t = threading.Thread(target=getCurentTagsItemsense args=(ip,job_id))
    threads.append(t)
    t.start()
    app.run_server(debug=True,host='0.0.0.0')