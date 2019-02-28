import pandas as pd
from annoy import AnnoyIndex
import matplotlib.pyplot as plt
import numpy as np
import math
import random

# For 3 coordinate vectors
t = AnnoyIndex(3, metric='euclidean')

t.load('centroids.tree')

# print(t.get_nns_by_vector([1,2,0], 1))

# Read json file as Pandas Series
history = pd.read_json('data1.json')['history']

# Parse all entries for device id then reduce to unique ones
device_ids = history.map(lambda x: x['epc']).unique()

results = {}

# Create device index in results dict
for id in device_ids:
  results[id] = {'pts':{}}

  for i in range(1, 4):
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


for r in results:
  zone1_amnt = len(results[r]['pts']['zone1'])
  zone2_amnt = len(results[r]['pts']['zone2'])
  zone3_amnt = len(results[r]['pts']['zone3'])

  in_zone1 = zone1_amnt > zone2_amnt and zone1_amnt > zone3_amnt
  in_zone2 = zone2_amnt > zone1_amnt and zone2_amnt > zone3_amnt
  in_zone3 = zone3_amnt > zone1_amnt and zone3_amnt > zone2_amnt

  if in_zone1:
    results[r]['location'] = 'zone 1'
  elif in_zone2:
    results[r]['location'] = 'zone 2'
  elif in_zone3:
    results[r]['location'] = 'zone 3'

# Print as Df for better display
print(pd.DataFrame(results))

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
