import os, csv, gzip, glob
import numpy as np
import pandas as pd
from django.conf import settings
from .models import FeatureSample

DATA_FILE  = getattr(settings, "AIWAF_CSV_PATH", "access_samples.csv")
CSV_HEADER = [
    "ip","path_len","kw_hits","resp_time",
    "status_idx","burst_count","total_404","label"
]

class CsvFeatureStore:
    @staticmethod
    def persist_rows(rows):
        new_file = not os.path.exists(DATA_FILE)
        with open(DATA_FILE, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if new_file:
                w.writerow(CSV_HEADER)
            w.writerows(rows)

    @staticmethod
    def load_matrix():
        if not os.path.exists(DATA_FILE):
            return np.empty((0,6))
        df = pd.read_csv(
            DATA_FILE,
            names=CSV_HEADER,
            skiprows=1,
            engine="python",
            on_bad_lines="skip"
        )
        feature_cols = CSV_HEADER[1:7]
        df[feature_cols] = df[feature_cols].apply(pd.to_numeric, errors="coerce").fillna(0)
        return df[feature_cols].to_numpy()

class DbFeatureStore:
    @staticmethod
    def persist_rows(rows):
        objs = []
        for ip,pl,kw,rt,si,bc,t404,label in rows:
            objs.append(FeatureSample(
                ip=ip, path_len=pl, kw_hits=kw,
                resp_time=rt, status_idx=si,
                burst_count=bc, total_404=t404,
                label=label
            ))
        FeatureSample.objects.bulk_create(objs, ignore_conflicts=True)

    @staticmethod
    def load_matrix():
        qs = FeatureSample.objects.all().values_list(
            "path_len","kw_hits","resp_time","status_idx","burst_count","total_404"
        )
        return np.array(list(qs), dtype=float)

def get_store():
    if getattr(settings, "AIWAF_FEATURE_STORE", "csv") == "db":
        return DbFeatureStore
    return CsvFeatureStore
