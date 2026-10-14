# SQLAlchemy models for AIWAF Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class AllowlistedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), unique=True, nullable=False)

class BlocklistedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), unique=True, nullable=False)
    reason = db.Column(db.String(255))
    extended_request_info = db.Column(db.JSON, nullable=True)
    reputation_reason = db.Column(db.String(500), default="")
    reasons = db.Column(db.JSON, nullable=True)
    score = db.Column(db.Integer, default=0)
    offenses = db.Column(db.Integer, default=0)
    blocked_at = db.Column(db.Float, nullable=True)
    expires_at = db.Column(db.Float, nullable=True)
    duration = db.Column(db.Integer, nullable=True)
    permanent = db.Column(db.Boolean, default=False)

class Keyword(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    keyword = db.Column(db.String(255), unique=True, nullable=False)

class GeoBlockedCountry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    country_code = db.Column(db.String(8), unique=True, nullable=False)


# Compatibility aliases for callers using the previous terminology.
WhitelistedIP = AllowlistedIP
BlacklistedIP = BlocklistedIP
