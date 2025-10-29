import pandas as pd
from cybersecurity_bot.config.config import DATASET_PATH

def check_dataset():
    df = pd.read_csv(DATASET_PATH)
    print("Class distribution:")
    print(df['is_suspicious'].value_counts())
    print("\nSample benign rows:")
    print(df[df['is_suspicious'] == 0].head())
    print("\nSample malicious rows:")
    print(df[df['is_suspicious'] == 1].head())
    
    # Print last 5 lines to confirm appended data
    print("\nLast 5 lines of the dataset:")
    print(df.tail(5))

if __name__ == "__main__":
    check_dataset()