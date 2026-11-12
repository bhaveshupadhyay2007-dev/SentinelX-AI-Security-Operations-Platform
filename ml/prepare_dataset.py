import pandas as pd
from pathlib import Path

SOURCE = Path("ml/source_data/malicious_phish.csv")
OUTPUT = Path("ml/dataset_public.csv")
REPORT = Path("ml/dataset_public_report.json")

BENIGN_SAMPLES = 30000
MALICIOUS_SAMPLES = 30000
RANDOM_STATE = 42


def main():
    print("Loading public dataset...")
    df = pd.read_csv(SOURCE)

    print(f"Original rows: {len(df)}")

    # Keep only required columns
    df = df[["url", "type"]].copy()

    # Remove missing values
    df["url"] = df["url"].astype(str).str.strip()
    df["type"] = df["type"].astype(str).str.strip().str.lower()

    df = df[df["url"].notna()]
    df = df[df["url"] != ""]
    df = df[df["type"].isin(["benign", "defacement", "phishing", "malware"])]

    # Remove duplicate URLs
    before_duplicates = len(df)
    df = df.drop_duplicates(subset=["url"], keep="first")
    duplicates_removed = before_duplicates - len(df)

    # Convert to binary classification
    df["label"] = df["type"].apply(
        lambda x: 0 if x == "benign" else 1
    )

    # Split classes
    benign = df[df["label"] == 0]
    malicious = df[df["label"] == 1]

    print(f"Clean benign rows: {len(benign)}")
    print(f"Clean malicious rows: {len(malicious)}")
    print(f"Duplicates removed: {duplicates_removed}")

    # Balanced sampling
    benign_sample = benign.sample(
        n=min(BENIGN_SAMPLES, len(benign)),
        random_state=RANDOM_STATE
    )

    malicious_sample = malicious.sample(
        n=min(MALICIOUS_SAMPLES, len(malicious)),
        random_state=RANDOM_STATE
    )

    final_df = pd.concat(
        [benign_sample, malicious_sample],
        ignore_index=True
    )

    # Shuffle final dataset
    final_df = final_df.sample(
        frac=1,
        random_state=RANDOM_STATE
    ).reset_index(drop=True)

    # Keep only the columns needed by the ML pipeline
    final_df = final_df[["url", "label"]]

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    final_df.to_csv(OUTPUT, index=False)

    report = {
        "source_rows": int(len(pd.read_csv(SOURCE))),
        "clean_benign_rows": int(len(benign)),
        "clean_malicious_rows": int(len(malicious)),
        "duplicates_removed": int(duplicates_removed),
        "final_rows": int(len(final_df)),
        "final_benign": int((final_df["label"] == 0).sum()),
        "final_malicious": int((final_df["label"] == 1).sum()),
        "random_state": RANDOM_STATE,
        "label_mapping": {
            "benign": 0,
            "defacement": 1,
            "phishing": 1,
            "malware": 1
        }
    }

    import json

    with open(REPORT, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    print()
    print("Dataset preparation complete.")
    print(f"Saved dataset: {OUTPUT}")
    print(f"Saved report: {REPORT}")
    print(f"Final rows: {len(final_df)}")
    print(f"Benign: {(final_df['label'] == 0).sum()}")
    print(f"Malicious: {(final_df['label'] == 1).sum()}")


if __name__ == "__main__":
    main()