import json
from pathlib import Path

import pandas as pd
import streamlit as st
import xgboost as xgb
from xgboost import XGBClassifier

from src.features import extract_features_v2

ROOT = Path(__file__).resolve().parent


@st.cache_resource
def load():
    model = XGBClassifier()
    model.load_model(str(ROOT / 'models' / 'phishing_xgb.json'))
    cols = json.load(open(ROOT / 'models' / 'feature_config.json'))['feature_order']
    return model, cols


model, cols = load()

st.title("Phishing URL checker")
st.caption("Looks at the URL text only and never visits the page. Treat the result as a signal, not a verdict.")

url = st.text_input("Paste a URL")
if url:
    row = pd.DataFrame([extract_features_v2(url)])[cols]
    p = float(model.predict_proba(row)[0][1])
    level = "Low risk" if p < 0.3 else "High risk" if p > 0.7 else "Uncertain"
    st.metric(level, f"{p:.0%} phishing probability")

    contribs = model.get_booster().predict(xgb.DMatrix(row), pred_contribs=True)[0][:-1]
    s = pd.Series(contribs, index=cols)
    st.subheader("What drove this score")
    for feat in s.abs().sort_values(ascending=False).head(5).index:
        direction = "raises" if s[feat] > 0 else "lowers"
        st.write(f"- `{feat}` = {row[feat].iloc[0]:.2f} {direction} the risk")
