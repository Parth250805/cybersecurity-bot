import pandas as pd

df = pd.read_csv('dataset.csv')

print("Class distribution:")
print(df['is_suspicious'].value_counts())

print("\nSample benign rows:")
print(df[df['is_suspicious'] == 0].head())

print("\nSample malicious rows:")
print(df[df['is_suspicious'] == 1].head())
