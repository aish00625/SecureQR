# import pandas as pd

# df = pd.read_csv("dataset\phishing_site_urls.csv")

# print(df.head())

# print("\nShape:")
# print(df.shape)

# print("\nColumns:")
# print(df.columns)

# print("\nLabels:")
# print(df['Label'].value_counts())
import cv2
from pyzbar.pyzbar import decode

cap = cv2.VideoCapture(0)

while True:
    ret,frame = cap.read()
    codes = decode(frame)

    for code in codes:
        data = code.data.decode()
        print(data)
    cv2.imshow("Scanner",frame)

    if cv2.waitKey(1) == 27:
        break

cap.release()
cv2.destroyAllWindows()