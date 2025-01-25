from fastapi import FastAPI, HTTPException, Depends, Request, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import FileResponse
from pydantic import BaseModel
from core.wifi_retriever import WiFiCredentialRetriever
from core.security_checks import SecurityCheck
from core.kill_switch import KillSwitch
from core.pin_authenticator import PinAuthenticator
from core.secure_qr_generator import SecureQRGenerator
from core.mfa import MFAManager
from core.behavioral_analytics import BehavioralAnalytics
from core.zkp import ZeroKnowledgeProver
from core.quantum_resistant import QuantumResistantCrypto
from core.secure_backup import SecureBackup
from core.geofencing import Geofence
from core.secure_sharing import SecureSharing
from core.network_analyzer import NetworkAnalyzer
from core.password_rotator import PasswordRotator
from core.secure_multiparty import SecureMultipartyComputation
from api.middleware import SecurityHeadersMiddleware
import logging
import os
from sqlalchemy.orm import Session
from core.database import get_db
from core import models
from cryptography.fernet import Fernet
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta

app = FastAPI()
app.add_middleware(SecurityHeadersMiddleware)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class RetrievalRequest(BaseModel):
    ssid: str
    platform: str
    pin: str
    totp: str
    latitude: float
    longitude: float

class UpdatePasswordRequest(BaseModel):
    ssid: str
    new_password: str
    platform: str

class SharingRequest(BaseModel):
    ssid: str
    platform: str
    duration: int

class UserCreate(BaseModel):
    username: str
    email: str
    password: str

# OAuth2 token authentication constants and utility functions
SECRET_KEY = "YOUR_SECRET_KEY"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(db, username)
    if user is None:
        raise credentials_exception
    return user

def authenticate_user(db: Session, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def get_user(db: Session, username: str):
    return db.query(models.User).filter(models.User.username == username).first()

logger = logging.getLogger("audit_log")
kill_switch = KillSwitch()
pin_auth = PinAuthenticator()
mfa_manager = MFAManager()
behavioral_analytics = BehavioralAnalytics()
zkp = ZeroKnowledgeProver()
qr_crypto = QuantumResistantCrypto()
secure_backup = SecureBackup(Fernet.generate_key())
geofence = Geofence(37.7749, -122.4194, 10)  
secure_sharing = SecureSharing()
network_analyzer = NetworkAnalyzer()
password_rotator = PasswordRotator(WiFiCredentialRetriever)
smc = SecureMultipartyComputation(total_parties=5, threshold=3)

@app.middleware("http")
async def kill_switch_check(request: Request, call_next):
    kill_switch.check_revocation()
    response = await call_next(request)
    return response

@app.post("/users/")
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    hashed_password = get_password_hash(user.password)
    db_user = models.User(username=user.username, email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/retrieve-wifi-password")
async def retrieve_wifi_password(
    request: RetrievalRequest,
    current_user: models.User = Depends(get_current_user),
    background_tasks: BackgroundTasks
):
    security_check = SecurityCheck()
    if not security_check.is_device_secure():
        logger.critical("Insecure device attempted retrieval")
        raise HTTPException(status_code=403, detail="Device security check failed")

    if not pin_auth.verify_pin(request.pin):
        logger.warning("Invalid PIN attempt")
        raise HTTPException(status_code=401, detail="Invalid PIN")

    if not mfa_manager.verify_totp(request.totp):
        logger.warning("Invalid TOTP attempt")
        raise HTTPException(status_code=401, detail="Invalid TOTP")

    if not geofence.is_within_fence(request.latitude, request.longitude):
        logger.warning("Access attempt outside geofence")
        raise HTTPException(status_code=403, detail="Access denied: Outside of authorized area")

    if not behavioral_analytics.is_behavior_normal(request.platform, request.latitude, request.longitude):
        logger.warning("Unusual behavior detected")
        raise HTTPException(status_code=403, detail="Unusual behavior detected")

    try:
        retriever = WiFiCredentialRetriever(request.platform)
        password = retriever.retrieve(request.ssid)
        
        if not zkp.verify_proof(password, zkp.generate_challenge(), zkp.generate_proof(password, zkp.generate_challenge())):
            raise HTTPException(status_code=401, detail="ZKP verification failed")

        logger.info(f"Successfully retrieved password for SSID: {request.ssid}")
        
        # Generate QR code
        qr_generator = SecureQRGenerator(request.ssid, password)
        qr_image = qr_generator.generate()
        qr_filename = f"wifi_qr_{request.ssid}.png"
        qr_image.save(qr_filename)
        
        # Backup the credential
        background_tasks.add_task(secure_backup.backup, {request.ssid: password}, f"{request.ssid}_backup.enc")
        
        # Analyze network and get recommendations
        analysis, recommendations = network_analyzer.analyze_and_recommend(request.ssid)
        
        # Schedule password rotation
        background_tasks.add_task(password_rotator.schedule_rotation, request.ssid)
        
        # Use quantum-resistant encryption for the response
        encrypted_password = qr_crypto.encrypt(password.encode(), qr_crypto.generate_shared_key(retriever.public_key))
        
        return {
            "ssid": request.ssid,
            "encrypted_password": encrypted_password.hex(),
            "qr_code": qr_filename,
            "network_analysis": analysis,
            "recommendations": recommendations
        }
    except Exception as e:
        logger.error(f"Password retrieval failed: {str(e)}")
        # If password retrieval fails, attempt to get the updated password
        try:
            updated_password = retriever.get_updated_password(request.ssid)
            if updated_password:
                logger.info(f"Retrieved updated password for SSID: {request.ssid}")
                # Generate new QR code and encrypt the updated password
                qr_generator = SecureQRGenerator(request.ssid, updated_password)
                qr_image = qr_generator.generate()
                qr_filename = f"wifi_qr_{request.ssid}_updated.png"
                qr_image.save(qr_filename)
                encrypted_password = qr_crypto.encrypt(updated_password.encode(), qr_crypto.generate_shared_key(retriever.public_key))
                return {
                    "ssid": request.ssid,
                    "encrypted_password": encrypted_password.hex(),
                    "qr_code": qr_filename,
                    "is_updated": True
                }
            else:
                raise HTTPException(status_code=404, detail="Updated password not found")
        except Exception as update_error:
            logger.error(f"Updated password retrieval failed: {str(update_error)}")
            raise HTTPException(status_code=500, detail="Password retrieval failed")

@app.post("/update-wifi-password")
async def update_wifi_password(
    request: UpdatePasswordRequest,
    current_user: models.User = Depends(get_current_user)
):
    try:
        # Verify user's authority to update the password
        if not current_user.has_permission_to_update(request.ssid):
            raise HTTPException(status_code=403, detail="User not authorized to update this password")

        # Update the password in the database
        retriever = WiFiCredentialRetriever(request.platform)
        success = retriever.update_password(request.ssid, request.new_password)

        if success:
            logger.info(f"Password updated successfully for SSID: {request.ssid}")
            return {"message": "Password updated successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to update password")
    except Exception as e:
        logger.error(f"Password update failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Password update failed")

@app.post("/share-wifi")
async def share_wifi(request: SharingRequest, current_user: models.User = Depends(get_current_user)):
    try:
        retriever = WiFiCredentialRetriever(request.platform)
        temp_password = secure_sharing.generate_temporary_password(request.ssid, retriever.retrieve(request.ssid), request.duration)
        return {"ssid": request.ssid, "temporary_password": temp_password, "duration": request.duration}
    except Exception as e:
        logger.error(f"WiFi sharing failed: {str(e)}")
        raise HTTPException(status_code=500, detail="WiFi sharing failed")

@app.post("/secure-multiparty-retrieval")
async def secure_multiparty_retrieval(ssid: str, current_user: models.User = Depends(get_current_user)):
    try:
        shares = smc.generate_partial_retrieval(smc.stored_shares.get(ssid, []))
        if not shares:
            raise HTTPException(status_code=404, detail="No stored shares for this SSID")
        password = smc.reconstruct_secret(shares)
        return {"ssid": ssid, "password": password}
    except Exception as e:
        logger.error(f"Secure multiparty retrieval failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Secure multiparty retrieval failed")

@app.get("/download-qr-code/{ssid}")
async def download_qr_code(ssid: str, current_user: models.User = Depends(get_current_user)):
    qr_filename = f"wifi_qr_{ssid}.png"
    if os.path.exists(qr_filename):
        return FileResponse(qr_filename, media_type="image/png", filename=qr_filename)
    raise HTTPException(status_code=404, detail="QR code not found")

@app.on_event("startup")
async def startup_event():
    # Initialize behavioral analytics model
    behavioral_analytics.train_model()
    
    # Start password rotation scheduler
    password_rotator.start()

@app.on_event("shutdown")
async def shutdown_event():
    # Stop password rotation scheduler
    password_rotator.stop()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, ssl_keyfile="key.pem", ssl_certfile="cert.pem")
