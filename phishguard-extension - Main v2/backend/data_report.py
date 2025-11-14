import os
import pandas as pd

HERE = os.path.dirname(__file__)
CSV = os.path.join(HERE, "labeled_urls.csv")
if not os.path.exists(CSV):
    raise FileNotFoundError(CSV)

df = pd.read_csv(CSV)
print("File:", CSV)
print("Total rows:", len(df))
if 'label' in df.columns:
    print('\nClass distribution:')
    print(df['label'].value_counts(dropna=False))
else:
    print('No label column found')

# URL uniqueness
if 'url' in df.columns:
    print('\nUnique URLs:', df['url'].nunique())
    dup_count = df['url'].duplicated().sum()
    print('Exact URL duplicates:', dup_count)
    if dup_count:
        print(df[df['url'].duplicated(keep=False)].sort_values('url'))

# Check for trimmed/lowercase duplicates
if 'url' in df.columns:
    cleaned = df['url'].astype(str).str.strip().str.lower()
    dup_clean = cleaned.duplicated().sum()
    print('\nDuplicates after lowercase+trim:', dup_clean)

# Basic preview
print('\nSample rows:')
print(df.head(10).to_string(index=False))
