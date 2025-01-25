# core/models.py

from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from .database import Base
import datetime

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    wifi_credentials = relationship("WiFiCredential", back_populates="owner")
    access_logs = relationship("AccessLog", back_populates="user")

class WiFiCredential(Base):
    __tablename__ = "wifi_credentials"

    id = Column(Integer, primary_key=True, index=True)
    ssid = Column(String, index=True)
    encrypted_password = Column(String)
    owner_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    owner = relationship("User", back_populates="wifi_credentials")

class AccessLog(Base):
    __tablename__ = "access_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    action = Column(String)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    ip_address = Column(String)
    device_type = Column(String)
    latitude = Column(Float)
    longitude = Column(Float)

    user = relationship("User", back_populates="access_logs")

class MFADevice(Base):
    __tablename__ = "mfa_devices"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    device_type = Column(String)  # e.g., "totp", "sms"
    secret_key = Column(String)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    user = relationship("User")

class SharedWiFi(Base):
    __tablename__ = "shared_wifi"

    id = Column(Integer, primary_key=True, index=True)
    wifi_credential_id = Column(Integer, ForeignKey("wifi_credentials.id"))
    temporary_password = Column(String)
    expiration_time = Column(DateTime)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    wifi_credential = relationship("WiFiCredential")

class NetworkAnalysis(Base):
    __tablename__ = "network_analyses"

    id = Column(Integer, primary_key=True, index=True)
    wifi_credential_id = Column(Integer, ForeignKey("wifi_credentials.id"))
    encryption_type = Column(String)
    signal_strength = Column(Float)
    last_analyzed = Column(DateTime, default=datetime.datetime.utcnow)

    wifi_credential = relationship("WiFiCredential")
