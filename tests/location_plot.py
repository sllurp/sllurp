from __future__ import print_function
import dash
import dash_core_components as dcc
import dash_html_components as html
import paho.mqtt.client as mqtt
import json
import time
import plotly.graph_objs as go
import numpy as np
from dash.dependencies import  Event, Output,Input
import plotly
import threading
epc = []
x_locations = []
y_locations = []
colors = []
timestamps = []
client = None
topic = None

mqtt_broker = "localhost"
mqtt_topic = "llrp/1"
lock = threading.Lock()
def on_message(cleint,userdata,message):
    refresh_tag_list(message.payload)

def refresh_tag_list(payload):
    lock.acquire()
    payload = json.loads(payload)
    print("received new mqtt" + str(payload))
    try:
        index = epc.index(payload["EPCData"])
    except ValueError:
        index = -1
    if index > -1:
        print("prev tag found" + payload["EPCData"]) 
        x_locations[index] = payload["LocXCentimeters"]
        y_locations[index] = payload["LocYCentimeters"]
        epc[index] = payload["EPCData"]
        timestamps[index] = payload["LastSeenTimestampUTC"]
        print("")
        print(timestamps)
        print(epc)
        print(x_locations)
        print(y_locations)
        print("")
        lock.release()
        return
    else:
        print("no prev tag found"+ payload["EPCData"])
        print(epc)
        x_locations.append(payload["LocXCentimeters"])
        y_locations.append(payload["LocYCentimeters"])
        epc.append(payload["EPCData"])
        colors.append(np.random.randn())
        timestamps.append(payload["LastSeenTimestampUTC"])
        print("")
        print(timestamps)
        print(epc)
        print(x_locations)
        print(y_locations)
        print("")
        lock.release()
        return

app = dash.Dash()

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

# @app.callback(Output('live-update-graph-scatter', 'figure'),
#               events=[Event('interval-component', 'interval')])
# def update_graph_scatter():

#     traces = plotly.graph_objs.Scatter(
#         x=x_locations,
#         y=y_locations,
#         text=epc,
#         mode= 'markers'
#         )
#     return {'data':traces}

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
    for index,t in enumerate(timestamps):
        print(millis - int(timestamps[index]))
        if abs(millis - int(timestamps[index])) < 250000000: #30 seconds

            print(millis)
            print("deleting stuff")
            del x_locations[index]
            del y_locations[index]
            del epc[index]
            del colors[index]
            del timestamps[index]
    lock.release()
    trace = go.Scatter(
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
    data = [trace]
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

def on_connect(client, userdata, flags, rc):
    print("Connected to MQTT BROKER with result code "+str(rc))


if __name__ == '__main__':
    client = mqtt.Client()
    client.on_message=on_message
    client.connect(mqtt_broker)
    client.on_connect = on_connect
    client.loop_start()

    client.subscribe(mqtt_topic)

    app.run_server(debug=True)
