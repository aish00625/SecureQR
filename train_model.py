import pandas as pd
from sklearn.svm import LinearSVC
import joblib

data = pd.read_csv("urls.csv")
X = data[['length', 'dots', 'https']]
y = data['label']

model = LinearSVC()
model.fit(X,y)
joblib.dump(model, 'svm_model.pkl')
print("Model Saved")