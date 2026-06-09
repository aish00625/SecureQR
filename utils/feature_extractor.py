import pandas as pd

def extract_features(url):

    length = len(url)

    dots = url.count('.')

    hyphens = url.count('-')

    digits = sum(c.isdigit() for c in url)

    at_symbol = 1 if '@' in url else 0

    https = 1 if url.startswith('https') else 0

    return [
        length,
        dots,
        hyphens,
        digits,
        at_symbol,
        https
    ]

df = pd.read_csv("dataset\phishing_site_urls.csv")

features = df['URL'].apply(extract_features)

feature_df = pd.DataFrame(
    features.tolist(),
    columns=[
        'length',
        'dots',
        'hyphens',
        'digits',
        'at_symbol',
        'https'
    ]
)

feature_df['label'] = df['Label'].map({
    'good':0,
    'bad':1
})

print(feature_df.head())