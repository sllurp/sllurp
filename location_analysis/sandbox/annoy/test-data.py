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
  results[id] = {}
  results[id]['pts'] = {}

  for i in range(1, 4):
    results[id][i] = 1
    results[id]['pts']['zone' + str(i)] = []



pts = []

for event in history:
  x = event['toX']
  y = event['toY']
  z = 0

  closest_zone, dist = t.get_nns_by_vector([x,y,z], 1, include_distances=True)

  closest_zone = closest_zone.pop()
  dist = math.sqrt(dist.pop()) # Squared by lib
  dev_id = event['epc']

  pts += [[x, y]]
  results[dev_id][closest_zone] += 1
  results[dev_id]['pts']['zone' + str(closest_zone)] += [[x, y]]

centroids = [
  t.get_item_vector(1)[:2],
  t.get_item_vector(2)[:2],
  t.get_item_vector(3)[:2]
]

for r in results:
  # plt.scatter(*zip(*results[r]['pts']),s=100, alpha=0.9)
  for i in range(1, 4):
    print(len(results[r]['pts']['zone' + str(i)]))
    if (len(results[r]['pts']['zone' + str(i)])):
      plt.scatter(*zip(*results[r]['pts']['zone' + str(i)]),s=100, alpha=0.9)


plt.show()
