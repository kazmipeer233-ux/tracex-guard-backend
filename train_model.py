import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

X = np.array([
 [1,1,1,0,0],
 [0,0,0,0,0],
 [1,1,0,1,0],
 [0,0,1,0,0]
])

y = np.array([1,0,1,0])

model = RandomForestClassifier()
model.fit(X,y)

joblib.dump(model,"malware_model.pkl")

print("Model created")