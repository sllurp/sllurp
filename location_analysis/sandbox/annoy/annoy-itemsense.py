import pandas as pd
from annoy import AnnoyIndex
#import matplotlib.pyplot as plt
import numpy as np
import math
import random
import requests
import argparse
import sys
if ((3, 0) <= sys.version_info <= (3, 9)):
    from urllib.parse import quote as urlParse
elif ((2, 0) <= sys.version_info <= (2, 9)):
    from urllib import quote as urlParse
import json

itemsenseIP = "172.16.80.169"
jobID = "0f4076db-7b9c-4e8b-afdb-5e2babf4541e"
username = "admin"
password = "mofasexy"
numZones = 12


def detect():
# For 3 coordinate vectors
  t = AnnoyIndex(3, metric='euclidean')

  t.load('centroids.tree')

  # print(t.get_nns_by_vector([1,2,0], 1))



  # Read json file as Pandas Series
  #history = pd.read_json('data1.json')['history']
  request = "http://" + urlParse(itemsenseIP) + "/itemsense/data/v1/items/show/history?jobId=" + urlParse(jobID) + "&zoneTransitionsOnly=false"
  jsonResults = requests.get(request,auth=(username, password)).json()
  history = pd.read_json(json.dumps(jsonResults))['history']

  # Parse all entries for device id then reduce to unique ones
  device_ids = history.map(lambda x: x['epc']).unique()

  results = {}

  # Create device index in results dict
  for id in device_ids:
    results[id] = {'pts':{}}

    for i in range(1, numZones + 1):
      results[id]['pts']['zone' + str(i)] = []



  for event in history:
    x = event['toX']
    y = event['toY']
    z = 0

    closest_zone, dist = t.get_nns_by_vector([x,y,z], 1, include_distances=True)

    closest_zone = closest_zone.pop()
    dist = math.sqrt(dist.pop()) # Squared by lib
    dev_id = event['epc']

    results[dev_id]['pts']['zone' + str(closest_zone)] += [[x, y]]

  tag_zone = []
  for epc,tag in results.items():
    max_count = 0
    for key,val in tag["pts"].items(): #for each zone
      if len(val) > max_count:
        zone = key
        max_count = len(val)
    tag_zone.append(dict({epc : zone}))

  print(tag_zone)

# centroids = [
#   t.get_item_vector(1)[:2],
#   t.get_item_vector(2)[:2],
#   t.get_item_vector(3)[:2]
# ]

# for r in results:
#   # plt.scatter(*zip(*results[r]['pts']),s=100, alpha=0.9)
#   for i in range(1, 4):
#     print(len(results[r]['pts']['zone' + str(i)]))
#     if (len(results[r]['pts']['zone' + str(i)])):
#       plt.scatter(*zip(*results[r]['pts']['zone' + str(i)]),s=100, alpha=0.9)

# plt.show()

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Itemsense Location Live Visualisation')

    parser.add_argument('jsonArgs',help='jsonArgs',type=str)
    args = parser.parse_args()

    j = json.loads(args.jsonArgs)
    username = j.get("username")
    password = j.get("password")
    itemsenseIP = j.get("itemsenseIP")
    zoneName = j.get("zoneName")
    jobID = j.get("jobID")

    detect()
