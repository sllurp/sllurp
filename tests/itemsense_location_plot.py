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
import argparse
from urllib.parse import quote_plus as urlParse
import json
from polylabel import polylabel
tags = []
ip = ""
jobID = ""
itemsenseIP = "" 
epc = []
epc_color = []
x_locations = []
y_locations = []
x_zones = []
y_zones = []
colors = []
threads = []
zonesCoords = [] # has the following structure [{"name" : name , "x":[],"y":[]},{"x":[],"y":[]}...] each dict is a zone
zonesMid = [] #[{"name": name, "x": x ,"y": y},{"name": name, "x": x ,"y": y}...] mid coords of each zone
lock = threading.Lock()


def getCurrentZoneTest():
    coords = []
    xZonesPoints = []
    yZonesPoints = []
    with open('test_zones.json') as f:
        zones = json.load(f).get("zones")
    for zone in zones:
        zonesPoints = zone.get("points")
        for point in zonesPoints:
            xZonesPoints.append(point.get("x"))
            yZonesPoints.append(point.get("y"))

    for zone in zones:
        zoneName = zone.get("name")
        zonesPoints = zone.get("points")
        x = []
        y = []
        for point in zonesPoints:
            x.append(int(point.get("x") * 100))
            y.append(int(point.get("y") * 100))
        z = {"name": zoneName, "x": x, "y" : y}
        coords.append(z)

    return xZonesPoints, yZonesPoints, coords

def getCurentTagsTest():
    global x_locations
    global y_locations
    while(True):
        lock.acquire()
        x_locations.clear()
        y_locations.clear()
        x_locations, y_locations = generateTagsLocation(zonesCoords)
        lock.release()
        time.sleep(2)

def generateTagsLocation(zoneCoordinates):
    x_loc = []
    y_loc = []
    for zone in zoneCoordinates:
        colors.append(np.random.randn())
        x_coords = zone.get("x")
        y_coords = zone.get("y")
        tempList = list(zip(x_coords,y_coords))
        coords = [list(elem) for elem in tempList]
        mid = polylabel([coords])
        x_loc.append(mid[0] / 100)
        y_loc.append(mid[1] / 100)
    return x_loc, y_loc

def getCurrentZoneItemSense(itemsenseIP, zoneName):
    xZonesPoints = []
    yZonesPoints = []
    r = requests.get('http://' + urlParse(itemsenseIP) + '/itemsense/configuration/v1/zoneMaps/show/' + urlParse(zoneName))
    jsonResults = r.json()
    zones = jsonResults.get("zones")
    for zone in zones:
        zonePoints = zone.get("points")
        for point in zonePoints:
            xZonesPoints.append(point.get("x"))
            yZonesPoints.append(point.get("y"))

    coords = []
    for zone in zones:
        zonesPoints = zone.get("points")
        zoneName = zone.get("name")
        x = []
        y = []
        for point in zonesPoints:
            x.append(int(point.get("x") * 100))
            y.append(int(point.get("y") * 100))
        z = {"name": zoneName, "x": x, "y" : y}
        coords.append(z)

    mid = []
    for zone in coords:
        x_coords = zone.get("x")
        y_coords = zone.get("y")
        tempList = list(zip(x_coords,y_coords))
        coords = [list(elem) for elem in tempList]
        middleCoords = polylabel([coords])
        mid.append({"name": zone.get("name"), "x" : middleCoords[0] / 100, "y": middleCoords[1] / 100})

    return xZonesPoints, yZonesPoints, mid

def getCurrentTagsItemsense(itemsenseIP,jobID):
    global x_locations
    global y_locations
    while(True):
        lock.acquire()
        r = requests.get('http://' + urlParse(itemsenseIP) + '/' + urlParse(jobID))
        jsonResults = r.json()
        items = jsonResults.get("items")
        tags.clear()
        epc.clear()
        x_locations.clear()
        y_locations.clear()
        for item in items:
            epc.append(item.get('epc'))
            colors.append(getTagColor(item.get('epc')))
            x_locations.append(item.get('xLocation'))
            y_locations.append(item.get('yLocation'))
            tag = {'epc': item.get('epc'), 'x' : item.get('xLocation'), 'y' : item.get('yLocation')}
            tags.append(tag)
        lock.release()
        time.sleep(2)

def getTagColor(epc):
    color = list(filter(lambda tag: tag['epc'] == epc, epc_color))
    if color:
        return color[0].get("color")
    else:
        color = np.random.randn()
        epc_color.append({"epc": epc, "color": color})
        return color

app = dash.Dash()

app.layout = html.Div(
    html.Div([
        #dcc.Graph(id='live-update-graph-scatter',animate=True),
        dcc.Graph(id='live-update-graph'),
        dcc.Interval(
            id='interval-component',
            interval=2*1000,
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
   
    trace_zones = go.Scatter(
        x=x_zones,
        y=y_zones,
        text="zone",
        hoverinfo="text",
        mode='markers+lines',
        marker=dict(
            size = 5,
            color = 'rgb(0, 0, 0)',
            opacity = 0.3,
        ),
        line = dict(
            color = ('rgb(0, 0, 0)'),
            dash = 'dash'
        )
    ) 

    trace_tags = go.Scatter(
        x=x_locations,
        y=y_locations,
        text=epc,
        mode='markers',
        hoverinfo = 'x+y+text',
        marker=dict(
            size = 10,
            color = colors,
            opacity = 0.7,
            
        )
    )
    
    lock.release()
    data = [trace_zones,trace_tags]
    layout = go.Layout(autosize=True,title='Tag Location', 
        xaxis=dict(range=[min(x_zones) - 2, max(x_zones) + 2],
        title='X Distance cm',
        tick0=0,
        dtick=2,
        ticklen=8,
        tickwidth=4,
        tickcolor='#000'
        ),
        yaxis=dict(range=[min(y_zones) - 2, max(y_zones) + 2],
        title='Y Distance cm',
        tick0=0,
        dtick=2,
        ticklen=8,
        tickwidth=4,
        tickcolor='#000'
        )
    )

    return go.Figure(data=data,layout=layout)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Itemsense Location Live Visualisation')
    parser.add_argument('--test', action='store_true', help="test mode")
    parser.add_argument('itemsenseIP', help='ItemsenseIP:Port')
    parser.add_argument('jobID', help='Itemsense Job ID')
    parser.add_argument('zoneName', help='Zone Name')
    args = parser.parse_args()
    if args.test:
        x_zones,y_zones,zonesCoords = getCurrentZoneTest()  
        t = threading.Thread(target=getCurentTagsTest)
        threads.append(t)
        t.start()
    else:
        x_zones, y_zones, zonesMid = getCurrentZoneItemSense(args.itemsenseIP,args.zoneName)
        t = threading.Thread(target=getCurrentTagsItemsense,args=(args.itemsenseIP,args.jobID,))
        threads.append(t)
        t.start()
    app.run_server(debug=True,host='0.0.0.0')