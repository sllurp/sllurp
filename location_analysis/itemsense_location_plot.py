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
from urllib.parse import quote as urlParse
import json
import random
from polylabel import polylabel
import math
from sklearn.ensemble import IsolationForest
import pandas as pd
tags = [] # [{'epc':epc,'x':[], 'y':[],'zone':'zone1'},{'epc':epc,'x':[], 'y':[],'zone':'[zone1,zone2,],'avg_x' = x, 'avg_y' = y}...]
outlier_tags = {'x':[0],'y':[0]}
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
graphUpdateInterval = 2
waitingStatus = ["WAITING","STARTING","INITIALIZING"]
username = "admin"
password = "mofasexy"
lock = threading.Lock()


#Isolation Forest Settings
contamination = 0.3
max_samples=100
behaviour='new'

def getJobStatus(itemsenseIP,jobID):
    request = 'http://' + urlParse(itemsenseIP) + '/itemsense/control/v1/jobs/show/' + urlParse(jobID)
    jsonResults = requests.get(request,auth=(username, password)).json()
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
    for zone in zonesMid:
        dist = math.hypot(x - zone.get("x"), y - zone.get("y"))
        if dist < minDist:
            minDist = dist
            currentZone = zone.get("name")
    return currentZone

def getCurrentZoneJson(filename):
    with open(filename) as f:
        jsonResults = json.load(f)
    return getCurrentZoneHelper(jsonResults)

def getCurrentZoneItemSense(itemsenseIP, zoneName):
    xZonesPoints = []
    yZonesPoints = []
    request  = 'http://' + urlParse(itemsenseIP) + '/itemsense/configuration/v1/zoneMaps/show/' + urlParse(zoneName)
    jsonResults = requests.get(request,auth=(username, password)).json()
    return getCurrentZoneHelper(jsonResults)

def getCurrentZoneHelper(jsonResults):
    xZonesPoints = []
    yZonesPoints = []
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
        request = 'http://' + urlParse(itemsenseIP) + '/itemsense/data/v1/items/show' 
        r = requests.get(request,auth=(username, password))
        jsonResults = r.json()
        items = jsonResults.get("items")
        tags.clear()

        for item in items:
            getTagColor(item.get('epc'))
            zone = getTagZone(item.get('xLocation'),item.get('yLocation'))
            tag = {'epc': item.get('epc'), 'x': [item.get('xLocation')], 'y': [item.get('yLocation')],'zone': [zone]}
            tags.append(tag)
        lock.release()
        time.sleep(2)


def getHistoryTagsJson(filename):
    global tags 
    global outlier_tags
    _tags = []
    with open(filename) as f:
        jsonResults = json.load(f)
    history = jsonResults.get("history")
    for historic_tag in history:
        if not _tags:
            zone = getTagZone(historic_tag.get("toX"),historic_tag.get("toY"))
            tag = {"epc":historic_tag["epc"],"x": [historic_tag["toX"]], "y": [historic_tag["toY"]], "zone":[zone]}
            _tags.append(tag)
        else:
            for i,item in enumerate(_tags):
                if item["epc"] == historic_tag["epc"]:
                    item["x"].append(historic_tag.get("toX"))
                    item["y"].append(historic_tag.get("toY"))
                    zone = getTagZone(historic_tag.get("toX"),historic_tag.get("toY"))
                    item["zone"].append(zone)
                    break
                else:
                    if(i == len(_tags) - 1):
                        zone = getTagZone(historic_tag.get("toX"),historic_tag.get("toY"))
                        tag = {"epc":historic_tag["epc"],"x": [historic_tag["toX"]], "y": [historic_tag["toY"]], "zone":[zone]}
                        _tags.append(tag)
    
    tags, outlier_tags = isolationForestProcessing(_tags)
        

def getHistoryTagsItemsense(itemsenseIP,jobID):
    global tags
    global outlier_tags
    _tags = []
    request = "http://" + urlParse(itemsenseIP) + "/itemsense/data/v1/items/show/history?jobId=" + urlParse(jobID) + "&zoneTransitionsOnly=false"
    print(request)
    jsonResults = requests.get(request,auth=(username, password)).json()
    history = jsonResults.get("history")
    for historic_tag in history:
        if not _tags:
            zone = getTagZone(historic_tag.get("toX"),historic_tag.get("toY"))
            tag = {"epc":historic_tag["epc"],"x": [historic_tag["toX"]], "y": [historic_tag["toY"]], "zone":[zone]}
            _tags.append(tag)
        else:
            for i,item in enumerate(_tags):
                if item["epc"] == historic_tag["epc"]:
                    item["x"].append(historic_tag.get("toX"))
                    item["y"].append(historic_tag.get("toY"))
                    zone = getTagZone(historic_tag.get("toX"),historic_tag.get("toY"))
                    item["zone"].append(zone)
                    break
                else:
                    if(i == len(_tags) - 1):
                        zone = getTagZone(historic_tag.get("toX"),historic_tag.get("toY"))
                        tag = {"epc":historic_tag["epc"],"x": [historic_tag["toX"]], "y": [historic_tag["toY"]], "zone":[zone]}
                        _tags.append(tag)
    
    tags, outlier_tags = isolationForestProcessing(_tags)

def getHistoryTagsHelper(jsonResults):
    tags = []
    history = jsonResults.get("history")
    for historic_tag in history:
        if not tags:
            zone = getTagZone(historic_tag.get("toX"),historic_tag.get("toY"))
            zone=historic_tag.get("toZone")
            tag = {"epc":historic_tag["epc"],"x": [historic_tag["toX"]], "y": [historic_tag["toY"]], "zone":[zone]}
            tags.append(tag)
        else:
            for i,item in enumerate(tags):
                if item["epc"] == historic_tag["epc"]:
                    item["x"].append(historic_tag.get("toX"))
                    item["y"].append(historic_tag.get("toY"))
                    zone = getTagZone(historic_tag.get("toX"),historic_tag.get("toY"))
                    item["zone"].append(zone)
                    break
                else:
                    if(i == len(tags) - 1):
                        print("appending tag to tags")
                        zone = getTagZone(historic_tag.get("toX"),historic_tag.get("toY"))
                        tag = {"epc":historic_tag["epc"],"x": [historic_tag["toX"]], "y": [historic_tag["toY"]], "zone":[zone]}
                        tags.append(tag)
    return tags


def isolationForestProcessing(raw_data):
  
    inaccurate_tags = {'x':[],'y':[]}

    for data in raw_data:
        test_data = pd.DataFrame(data={'x': data.get("x") , 'y': data.get("y")})

        clf = IsolationForest(behaviour = behaviour, max_samples = max_samples, contamination = contamination)
        pred = clf.fit_predict(test_data)

        for i,item in enumerate(pred):
            if item == -1: 
                #print(str(len(data.get('x'))) + " " + str(i) +  " " + str(len(pred)))
                inaccurate_tags.get('x').append(data.get('x')[i])
                inaccurate_tags.get('y').append(data.get('y')[i])
        
        #Remove the outliers from the original dataset
        x = [e for e in data.get("x") if e not in inaccurate_tags.get('x')]
        y = [e for e in data.get("y") if e not in inaccurate_tags.get('y')]
        if contamination >= 0.4:
            if x:
                data["x"] = x
            if y:
                data["y"] = y
        else:
            data["x"] = x
            data["y"] = y
        data["avg_x"] = np.median(data["x"])
        data["avg_y"] = np.median(data["y"])
        data["avg_zone"] = getTagZone(data["avg_x"],data["avg_y"])

    return raw_data, inaccurate_tags

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
    lock.acquire()
    traceZones = go.Scatter(
        x=x_zones,
        y=y_zones,
        text=mapName,
        hoverinfo="text+x+y",
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
            text=tag.get("zone"),
            mode='markers',
            hoverinfo = 'none',
            marker=dict(
                size = 7,
                color = getTagColor(tag.get("epc")),
                opacity = 0.6,
            ),
            name=tag.get("epc")
        )
        traceAvgTag = go.Scatter(
            x=[tag.get("avg_x",0)],
            y=[tag.get("avg_y",0)],
            text=tag.get("avg_zone",0),
            mode='markers',
            hoverinfo = 'x+y+text',
            marker=dict(
                size = 15,
                color = getTagColor(tag.get("epc")),
                opacity = 1.0,
            ),
            name= "Avg " + tag.get("epc")
        )
        plot.append(traceTag)
        plot.append(traceAvgTag)

    traceOutliers = go.Scatter(
        x=outlier_tags.get('x'),
        y=outlier_tags.get('y'),
        hoverinfo="none",
        mode='markers',
        marker=dict(
            size = 5,
            color = 'rgb(255, 0, 0)',
            opacity = 0.5,
        ),
        name="Bad Detection"
    )
    plot.append(traceOutliers)
    #print(plot)
    lock.release()
    data = plot
    layout = go.Layout(autosize=True,title='Tag Location with Isolation Forest with Contamination of ' +  str(contamination) + " Sample Size " + str(max_samples), 
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
    
    parser.add_argument('-u', '--username', help='username',type=str )
    parser.add_argument('-p','--password', help='password',type=str)

    parser.add_argument('-ip','--itemsenseIP', help='ItemsenseIP',type=str)
    parser.add_argument('-z','--zoneName', help='Zone Name',type=str)
    parser.add_argument('-j','--jobID', help='Itemsense Job ID',type=str)

    parser.add_argument('-d','--jsonData', help='json data filename',type=str)
    parser.add_argument('-zd','--zoneData', help='zone data filename',type=str)

    parser.add_argument('mode',help='Operation Mode',type=str, choices=["itemsense","test","json"])
    args = parser.parse_args()

    if args.mode == "test":
        x_zones, y_zones, zonesCoords, zonesMid, mapName = getCurrentZoneTest()
        t = threading.Thread(target=getCurentTagsTest,args=(zonesCoords,))
        threads.append(t)
        t.start()
    elif args.mode == "json":
        x_zones, y_zones, zonesMid, mapName = getCurrentZoneJson(args.zoneData)
        getHistoryTagsJson(args.jsonData)
    else:
        username = args.username
        password = args.password
        x_zones, y_zones, zonesMid, mapName = getCurrentZoneItemSense(args.itemsenseIP,args.zoneName)
        status = getJobStatus(args.itemsenseIP,args.jobID)
        while status in waitingStatus:
            status = getJobStatus(args.itemsenseIP,args.jobID)
            time.sleep(1)
            print(status)
        if status == "STOPPED":
            print("Getting Historical Data")
            getHistoryTagsItemsense(args.itemsenseIP,args.jobID)
            graphUpdateInterval = 100
        elif status == "RUNNING":
            print("Getting Live Data")
            t = threading.Thread(target=getCurrentTagsItemsense,args=(args.itemsenseIP,args.jobID,))
            threads.append(t)
            t.start()
        if status == "ERROR":
            print("invalid jobID")
            exit
    app.run_server(debug=True,host='0.0.0.0')