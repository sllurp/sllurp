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
import random
from polylabel import polylabel
import math
tags = [] # [{'epc':epc,'x':[], 'y':[],'zone':'zone1'},{'epc':epc,'x':[], 'y':[],'zone':'zone1'}...]
ip = ""
jobID = ""
itemsenseIP = ""
epc = []
epcColor = {}
x_locations = []
y_locations = []
x_zones = []
y_zones = []
colors = []
threads = []
plot = []
mapName = ""
zonesCoords = [] # has the following structure [{"name" : name , "x":[],"y":[]},{"x":[],"y":[]}...] each dict is a zone
zonesMid = [] #[{"name": name, "x": x ,"y": y},{"name": name, "x": x ,"y": y}...] mid coords of each zone
graphUpdateInterval = 1
waitingStatus = ["WAITING","STARTING","INITIALIZING"]
lock = threading.Lock()


def getJobStatus(jobID):
    r = requests.get('http://' + urlParse(itemsenseIP) + '/control/v1/jobs/show/' + urlParse(jobID))
    jsonResults = r.json()
    return jsonResults.get("status")


def getCurrentZoneTest():
    coords = []
    xZonesPoints = []
    yZonesPoints = []
    with open('test_zones.json') as f:
        j = json.load(f)
        zones = j.get("zones")
        mapName = j.get("name")
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

    mid = []
    for zone in coords:
        x_coords = zone.get("x")
        y_coords = zone.get("y")
        tempList = list(zip(x_coords,y_coords))
        temp = [list(elem) for elem in tempList]
        middleCoords = polylabel([temp])
        mid.append({"name": zone.get("name"), "x" : middleCoords[0] / 100, "y": middleCoords[1] / 100})


    return xZonesPoints, yZonesPoints, coords, mid, mapName

def getCurentTagsTest(zoneCoordinates):
    global x_locations
    global y_locations
    global tags
    while(True):
        lock.acquire()
        tags.clear()
        tags = generateTagsLocation(zoneCoordinates)
        lock.release()
        time.sleep(2)

def generateTagsLocation(zoneCoordinates):
    randomTags = []
    epcColor.clear()
    for zone in zoneCoordinates:
        x_coords = zone.get("x")
        y_coords = zone.get("y")
        tempList = list(zip(x_coords,y_coords))
        coords = [list(elem) for elem in tempList]
        mid = polylabel([coords])
        x_loc = ((mid[0] / 100) + random.uniform(-0.5, 0.5) )
        y_loc = ((mid[1] / 100) + random.uniform(-0.5, 0.5) )
        epc = random.randint(1,9999)
        getTagColor(epc)
        zone = getTagZone(x_loc,y_loc)
        randomTags.append({'epc':epc,'x':[round(x_loc,2)],'y':[round(y_loc,2)],'zone': zone})
    return randomTags

def getTagZone(x,y):
    currentZone = "none"
    minDist = 99999
    for zone in zoneMid:
        dist = math.hypot(x - zone.get("x"), y - zone.get("y"))
        if dist < minDist:
            minDist = dist
            currentZone = zone.get("name")
    return currentZone

def getCurrentZoneItemSense(itemsenseIP, zoneName):
    xZonesPoints = []
    yZonesPoints = []
    r = requests.get('http://' + urlParse(itemsenseIP) + '/itemsense/configuration/v1/zoneMaps/show/' + urlParse(zoneName))
    jsonResults = r.json()
    zones = jsonResults.get("zones")
    mapName = jsonResults.get("name")
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

    return xZonesPoints, yZonesPoints, mid, mapName

def getCurrentTagsItemsense(itemsenseIP,jobID):
    global x_locations
    global y_locations
    global tags
    while(True):
        lock.acquire()
        r = requests.get('http://' + urlParse(itemsenseIP) + '/data/v1/items/show/?jobId=' + urlParse(jobID))
        jsonResults = r.json()
        items = jsonResults.get("items")
        tags.clear()
        #epc.clear()
        #x_locations.clear()
        #y_locations.clear()
        for item in items:
            #epc.append(item.get('epc'))
            getTagColor(item.get('epc'))
            #colors.append(getTagColor(item.get('epc')))
            #x_locations.append(item.get('xLocation'))
            #y_locations.append(item.get('yLocation'))
            zone = getTagZone(item.get('xLocation'),item.get('yLocation'))
            tag = {'epc': item.get('epc'), 'x': [item.get('xLocation')], 'y': [item.get('yLocation')],'zone': zone}
            tags.append(tag)
        lock.release()
        time.sleep(2)

def getHistoryTagsItemsense(itemsenseIP,jobID):
    return 0

def getTagColor(epc):
    if epc in epcColor:
        return epcColor.get(epc)
    else:
        color = 'rgb(' + str(random.randint(0,255)) + ',' + str(random.randint(0,255)) + ',' + str(random.randint(0,255)) + ')'
        epcColor.update({epc:color})
        return color

app = dash.Dash()

app.layout = html.Div(
    html.Div([
        #dcc.Graph(id='live-update-graph-scatter',animate=True),
        dcc.Graph(id='live-update-graph'),
        dcc.Interval(
            id='interval-component',
            interval= graphUpdateInterval *1000,
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
    traceZones = go.Scatter(
        x=x_zones,
        y=y_zones,
        text=mapName,
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
        ),
        name=mapName
    )
    plot.clear()
    plot.append(traceZones)
    for tag in tags:
        traceTag = go.Scatter(
            x=tag.get("x"),
            y=tag.get("y"),
            text="zone " + tag.get("zone"),
            mode='markers',
            hoverinfo = 'x+y+text',
            marker=dict(
                size = 10,
                color = getTagColor(tag.get("epc")),
                opacity = 0.7,
            ),
            name=tag.get("epc")
        )
        plot.append(traceTag)
    #print(plot)
    lock.release()
    data = plot
    layout = go.Layout(autosize=True,title='Tag Location', 
        xaxis=dict(range=[min(x_zones) - 2, max(x_zones) + 2],
        title='X Distance m',
        tick0=0,
        dtick=2,
        ticklen=8,
        tickwidth=4,
        tickcolor='#000'
        ),
        yaxis=dict(range=[min(y_zones) - 2, max(y_zones) + 2],
        title='Y Distance m',
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
        x_zones, y_zones, zonesCoords, zoneMid, mapName = getCurrentZoneTest()
        t = threading.Thread(target=getCurentTagsTest,args=(zonesCoords,))
        threads.append(t)
        t.start()
    else:
        x_zones, y_zones, zonesMid, mapName = getCurrentZoneItemSense(args.itemsenseIP,args.zoneName)
        status = getJobStatus(args.jobID)
        while status in waitingStatus:
            status = getJobStatus(args.jobID)
            time.sleep(1)
        if status == "STOPPED":
            getHistoryTagsItemsense(args.itemsenseIP,args.jobID)
            graphUpdateInterval = 600000
        elif status == "RUNNING":
            t = threading.Thread(target=getCurrentTagsItemsense,args=(args.itemsenseIP,args.jobID,))
            threads.append(t)
            t.start()
        if status == "ERROR":
            print("invalid jobID")
            exit
    app.run_server(debug=True,host='0.0.0.0')