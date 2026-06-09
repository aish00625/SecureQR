import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.svm import LinearSVC
from sklearn.metrics import accuracy_score
import joblib

def extract_features(url):
    length = len(url)
    dots = url.count('.')
    hyphens = url.count('-')
    digits = sum(c.isdigit() for c in url)
    at_symbol = 1 if '@' in url else 0
    https = 1 if url.startswith('https') else 0
    return [length, dots, hyphens, digits, at_symbol, https]

print("Loading dataset...")
df = pd.read_csv("dataset\phishing_site_urls.csv")

print("Creating features...")
features = df['URL'].apply(extract_features)

X = pd.DataFrame(
    features.tolist(), columns = ['length', 'dots', 'hyphens', 'digits', 'at_symbol','https'])

y = df['Label'].map({'good' :0, 'bad':1})
print("Splitting dataset...")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)
print("Training model...")
model = LinearSVC()
model.fit(X_train, y_train)
print("Predicting...")
predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)
print("Accuracy:",accuracy)

joblib.dump(model,"svm_model.pkl")
print("Model Saved")