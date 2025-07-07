def assess_risk(result, config):
    score = result.get("risk_score", 50)
    return {"score": score}
