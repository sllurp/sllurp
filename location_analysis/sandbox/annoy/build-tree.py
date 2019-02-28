import pandas as pd
from annoy import AnnoyIndex

'''
Process zones file to build decision tree
'''
# Read json file as Pandas Series
zones = pd.read_json('zone.json')['zones']

# Map as tuple
tuples = zones.map(lambda x: (x['name'], x['points']))

# Calculate mean point (centroid) for each zone
tuples_with_centroids = tuples.map(
  lambda x: (x[0], pd.DataFrame(x[1]).mean(axis=0).to_list())
)

centroids = tuples_with_centroids.tolist()
print(centroids)

# For 3 coordinate vectors
t = AnnoyIndex(3, metric='euclidean')

for i, cen in centroids:
    # Add each centroid to the decision tree
    t.add_item(int(i), cen)

'''
Build and save decision tree for future use
'''
t.build(len(centroids))

t.save('centroids.tree')
