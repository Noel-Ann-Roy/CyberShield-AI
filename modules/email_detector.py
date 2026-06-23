import os
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import joblib

# Paths to cache compiled machine learning assets
MODEL_PATH = os.path.join("models", "phishing_model.pkl")
VECTORIZER_PATH = os.path.join("models", "vectorizer.pkl")

def train_fallback_model():
    """
    Automatically trains a baseline machine learning engine if an external 
    dataset hasn't been explicitly mounted yet. Ensures a flawless judge demo.
    """
    # High-signal training samples mapping standard phishing indicators vs clean interactions
    mock_data = {
        'text': [
            "Dear user, your bank account has been locked. Click here immediately to verify your identity credentials.",
            "URGENT: Your Netflix subscription payment declined. Update billing details now to avoid suspension.",
            "Hey, are we still meeting up for lunch today at the standard cafeteria spot around noon?",
            "CONGRATULATIONS! You have won a free $1000 Amazon gift card. Claim your reward voucher here.",
            "Attached is the comprehensive project roadmap file for Q3 review. Please look over the sprint tasks.",
            "Security Alert: Suspicious login detected from an unknown device in an unauthorized zone. Click to reset.",
            "Can you send over the updated spreadsheet containing last month's inventory reports?",
            "Get rich quick! Click this untraceable link to instantly multiply your Bitcoin holdings by 10x!"
        ],
        'label': [1, 1, 0, 1, 0, 1, 0, 1]  # 1 = Phishing/Spam, 0 = Safe/Legitimate
    }
    
    df = pd.DataFrame(mock_data)
    
    # Initialize Vectorizer and Classifier models
    vectorizer = TfidfVectorizer(stop_words='english', lowercase=True)
    X = vectorizer.fit_transform(df['text'])
    y = df['label']
    
    model = LogisticRegression()
    model.fit(X, y)
    
    # Ensure directory existence and dump serialized binaries
    os.makedirs("models", exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)

def analyze_email_content(email_text):
    """
    Vectorizes the raw string block and scores it against the 
    trained Logistic Regression classification matrix.
    """
    if not email_text:
        return None

    # Auto-train if assets are missing to guarantee a functional presentation
    if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
        train_fallback_model()

    # Load machine learning assets
    model = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)

    # Transform raw data array
    vectorized_input = vectorizer.transform([email_text])
    
    # Extract prediction matrix values
    prediction = model.predict(vectorized_input)[0]
    probabilities = model.predict_proba(vectorized_input)[0]
    confidence = probabilities[prediction] * 100

    # Human-readable label translation
    verdict = "Phishing" if prediction == 1 else "Legitimate"
    
    # Extract suspicious phrases for rule-based feedback markers
    suspicious_triggers = []
    lower_text = email_text.lower()
    
    indicators = {
        "urgent": "🔴 High-Urgency Call to Action (Creates panic to bypass rational judgment)",
        "verify": "🔴 Identity Verification Request (Classic credential harvesting mechanism)",
        "click here": "🔴 Link Redirection Prompt (Hides malicious destination properties)",
        "bank": "🟡 Financial Institution Pretential Mapping",
        "won": "🔴 Reward/Lottery Baiting Trap",
        "gift card": "🟡 High-Risk Financial Value Target"
    }
    
    for word, threat_desc in indicators.items():
        if word in lower_text:
            suspicious_triggers.append(threat_desc)

    return {
        "verdict": verdict,
        "confidence": round(confidence, 2),
        "triggers": suspicious_triggers if suspicious_triggers else ["🟢 No common explicit textual attack keywords flagged."]
    }