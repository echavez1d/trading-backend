from fastapi import FastAPI, HTTPException, Depends, status, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import os
import uuid
import httpx
import asyncio
from typing import Optional, List, Dict, Any
from cryptography.fernet import Fernet
import json
import hashlib
import hmac
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="Stock Trading & Investment Platform", version="1.8")

@app.on_event("startup")
async def create_indexes():
    await users_collection.create_index("email", unique=True)
    await users_collection.create_index("id", unique=True)
    await api_keys_collection.create_index("user_email")
    await api_keys_collection.create_index("id", unique=True)
    # Add more as needed for other collections

# CORS middleware for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"], # Adjust as needed for your frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# JWT Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # 24 hours

# Encryption setup for API keys
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", Fernet.generate_key().decode())
fernet = Fernet(ENCRYPTION_KEY.encode() if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY)

# MongoDB setup
client = AsyncIOMotorClient(os.getenv("MONGO_URL"))
db = client[os.getenv("DB_NAME", "trading_platform")]

# Collections
users_collection = db.users
watchlists_collection = db.watchlists
api_keys_collection = db.api_keys
trading_logs_collection = db.trading_logs
notes_collection = db.notes
news_collection = db.news
trades_collection = db.trades

# Pydantic models
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str
    remember_me: Optional[bool] = False

class APIKeyCreate(BaseModel):
    provider: str  # 'finnhub', 'alpaca_paper', 'alpaca_live', 'coingecko'
    api_key: str
    secret_key: Optional[str] = None
    environment: str = "paper"  # 'paper' or 'live'

class WatchlistCreate(BaseModel):
    name: str
    symbols: List[str]
    description: Optional[str] = None

class StockQuote(BaseModel):
    symbol: str
    price: float
    change: float
    change_percent: float
    volume: int
    market_cap: Optional[int] = None

# Authentication functions
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        user = await users_collection.find_one({"email": email})
        if user is None:
            raise credentials_exception
        return user
    except JWTError:
        raise credentials_exception

# Encryption utilities
def encrypt_api_key(api_key: str) -> str:
    return fernet.encrypt(api_key.encode()).decode()

def decrypt_api_key(encrypted_key: str) -> str:
    return fernet.decrypt(encrypted_key.encode()).decode()

# Finnhub API integration
class FinnhubClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://finnhub.io/api/v1"
        
    async def get_quote(self, symbol: str) -> Dict[str, Any]:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/quote",
                params={"symbol": symbol, "token": self.api_key}
            )
            return response.json()
    
    async def search_stocks(self, query: str) -> Dict[str, Any]:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/search",
                params={"q": query, "token": self.api_key}
            )
            return response.json()
    
    async def get_company_profile(self, symbol: str) -> Dict[str, Any]:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/stock/profile2",
                params={"symbol": symbol, "token": self.api_key}
            )
            return response.json()

    async def get_company_news(self, symbol: str, from_date: str, to_date: str):
        """Get company-specific news"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/company-news",
                params={
                    "symbol": symbol, 
                    "from": from_date, 
                    "to": to_date,
                    "token": self.api_key
                }
            )
            return response.json()
    
    async def get_market_news(self, category: str = "general"):
        """Get general market news"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/news",
                params={
                    "category": category,
                    "token": self.api_key
                }
            )
            return response.json()

# Alpaca Trading API integration
class AlpacaClient:
    def __init__(self, api_key: str, secret_key: str, base_url: str = "https://paper-api.alpaca.markets"):
        import alpaca_trade_api as tradeapi
        self.api = tradeapi.REST(
            key_id=api_key,
            secret_key=secret_key,
            base_url=base_url,
            api_version='v2'
        )
    
    def get_account(self):
        return self.api.get_account()
    
    def get_positions(self):
        return self.api.list_positions()
    
    def place_order(self, symbol: str, qty: float, side: str, order_type: str = 'market', time_in_force: str = 'gtc', limit_price: Optional[float] = None):
        order_data = {
            'symbol': symbol,
            'qty': qty,
            'side': side,
            'type': order_type,
            'time_in_force': time_in_force
        }
        
        if order_type == 'limit' and limit_price:
            order_data['limit_price'] = limit_price
            
        return self.api.submit_order(**order_data)
    
    def get_orders(self, status: str = 'all'):
        return self.api.list_orders(status=status)
    
    def get_order_by_id(self, order_id: str):
        """Get specific order details"""
        return self.api.get_order(order_id)
    
    def get_assets(self, status: str = 'active'):
        """Get list of tradable assets"""
        return self.api.list_assets(status=status)
    
    def is_tradable(self, symbol: str):
        """Check if a symbol is tradable"""
        try:
            asset = self.api.get_asset(symbol)
            return asset.tradable and asset.status == 'active'
        except:
            return False
    
    def validate_connection(self):
        """Validate API connection"""
        try:
            account = self.api.get_account()
            return True, f"Connected successfully. Account: {account.account_number}"
        except Exception as e:
            return False, f"Connection failed: {str(e)}"

# CoinGecko Crypto API integration  
class CoinGeckoClient:
    def __init__(self, api_key: Optional[str] = None):
        from pycoingecko import CoinGeckoAPI
        if api_key:
            self.api = CoinGeckoAPI(api_key=api_key)
        else:
            self.api = CoinGeckoAPI()  # Free tier
    
    def get_price(self, coin_ids: List[str], vs_currencies: str = 'usd'):
        return self.api.get_price(ids=coin_ids, vs_currencies=vs_currencies, include_24hr_change=True)
    
    def get_trending(self):
        return self.api.get_search_trending()
    
    def get_top_coins(self, limit: int = 10):
        return self.api.get_coins_markets(
            vs_currency='usd',
            order='market_cap_desc',
            per_page=limit,
            page=1,
            sparkline=False,
            price_change_percentage='24h'
        )

# New Pydantic models for trading and crypto
class OrderCreate(BaseModel):
    symbol: str
    quantity: float
    side: str  # 'buy' or 'sell'
    order_type: str = 'market'  # 'market' or 'limit'
    limit_price: Optional[float] = None

class CryptoRequest(BaseModel):
    coin_ids: List[str]

class NoteCreate(BaseModel):
    title: str
    content: str
    tags: Optional[List[str]] = []

class NoteUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    tags: Optional[List[str]] = None

class NewsSearch(BaseModel):
    query: Optional[str] = None
    symbols: Optional[List[str]] = None
    category: str = "general"

class TradeRecord(BaseModel):
    symbol: str
    side: str  # 'buy' or 'sell'
    quantity: float
    price: float
    order_id: str
    executed_at: datetime
    trading_mode: str

class AccountSwitchRequest(BaseModel):
    trading_mode: str

# API Routes

@app.post("/api/auth/register")
async def register(user: UserCreate):
    # Check if user already exists
    existing_user = await users_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create new user
    user_dict = {
        "id": str(uuid.uuid4()),
        "email": user.email,
        "full_name": user.full_name,
        "hashed_password": get_password_hash(user.password),
        "created_at": datetime.utcnow(),
        "is_active": True,
        "trading_mode": "paper",  # Default to paper trading
        "mfa_enabled": False
    }
    
    await users_collection.insert_one(user_dict)
    
    # Create access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer", "user": {
        "email": user.email,
        "full_name": user.full_name,
        "trading_mode": "paper"
    }}

@app.post("/api/auth/login")
async def login(user: UserLogin):
    db_user = await users_collection.find_one({"email": user.email})
    if not db_user or not verify_password(user.password, db_user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Set expiry: 30 days if remember_me, else 1 day
    if user.remember_me:
        access_token_expires = timedelta(days=30)
    else:
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer", "user": {
        "email": db_user["email"],
        "full_name": db_user["full_name"],
        "trading_mode": db_user.get("trading_mode", "paper")
    }}

@app.get("/api/auth/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    # Get user's API keys count for UI feedback
    api_keys_count = await api_keys_collection.count_documents({
        "user_email": current_user["email"],
        "is_active": True
    })
    
    # Check if key configurations exist for different providers
    has_finnhub = await api_keys_collection.find_one({
        "user_email": current_user["email"],
        "provider": "finnhub",
        "is_active": True
    }) is not None
    
    has_alpaca_paper = await api_keys_collection.find_one({
        "user_email": current_user["email"],
        "provider": "alpaca",
        "environment": "paper",
        "is_active": True
    }) is not None
    
    has_alpaca_live = await api_keys_collection.find_one({
        "user_email": current_user["email"],
        "provider": "alpaca",
        "environment": "live",
        "is_active": True
    }) is not None
    
    has_coingecko = await api_keys_collection.find_one({
        "user_email": current_user["email"],
        "provider": "coingecko",
        "is_active": True
    }) is not None
    
    return {
        "email": current_user["email"],
        "full_name": current_user["full_name"],
        "trading_mode": current_user.get("trading_mode", "paper"),
        "mfa_enabled": current_user.get("mfa_enabled", False),
        "api_keys_count": api_keys_count,
        "api_status": {
            "finnhub": has_finnhub,
            "alpaca_paper": has_alpaca_paper,
            "alpaca_live": has_alpaca_live,
            "coingecko": has_coingecko
        }
    }

@app.get("/api/auth/available-accounts")
async def get_available_accounts(current_user: dict = Depends(get_current_user)):
    """Get list of available trading accounts based on valid API keys"""
    
    # Check for valid Alpaca API keys
    paper_key = await api_keys_collection.find_one({
        "user_email": current_user["email"],
        "provider": "alpaca",
        "environment": "paper",
        "is_active": True
    })
    
    live_key = await api_keys_collection.find_one({
        "user_email": current_user["email"],
        "provider": "alpaca",
        "environment": "live", 
        "is_active": True
    })
    
    available_accounts = []
    
    # Validate paper account
    if paper_key:
        try:
            api_key = decrypt_api_key(paper_key["encrypted_api_key"])
            secret_key = decrypt_api_key(paper_key["encrypted_secret_key"])
            alpaca_client = AlpacaClient(api_key, secret_key, "https://paper-api.alpaca.markets")
            is_valid, message = alpaca_client.validate_connection()
            
            available_accounts.append({
                "mode": "paper",
                "name": "Paper Trading",
                "description": "Practice trading with virtual money",
                "valid": is_valid,
                "status": message,
                "icon": "🧪"
            })
        except Exception as e:
            available_accounts.append({
                "mode": "paper",
                "name": "Paper Trading", 
                "description": "Practice trading with virtual money",
                "valid": False,
                "status": f"Configuration error: {str(e)}",
                "icon": "🧪"
            })
    
    # Validate live account
    if live_key:
        try:
            api_key = decrypt_api_key(live_key["encrypted_api_key"])
            secret_key = decrypt_api_key(live_key["encrypted_secret_key"])
            alpaca_client = AlpacaClient(api_key, secret_key, "https://api.alpaca.markets")
            is_valid, message = alpaca_client.validate_connection()
            
            available_accounts.append({
                "mode": "live",
                "name": "Live Trading",
                "description": "Real money trading",
                "valid": is_valid,
                "status": message,
                "icon": "💰"
            })
        except Exception as e:
            available_accounts.append({
                "mode": "live",
                "name": "Live Trading",
                "description": "Real money trading", 
                "valid": False,
                "status": f"Configuration error: {str(e)}",
                "icon": "💰"
            })
    
    current_mode = current_user.get("trading_mode", "paper")
    
    return {
        "available_accounts": available_accounts,
        "current_mode": current_mode,
        "can_switch": len([acc for acc in available_accounts if acc["valid"]]) > 1
    }

@app.post("/api/auth/switch-trading-mode")
async def switch_trading_mode(request: AccountSwitchRequest, current_user: dict = Depends(get_current_user)):
    # Get available accounts to validate the switch
    available_accounts = await get_available_accounts(current_user)
    
    # Check if the requested mode is available and valid
    valid_modes = [acc["mode"] for acc in available_accounts.get("available_accounts", []) if acc["valid"]]
    
    if request.trading_mode not in valid_modes:
        raise HTTPException(
            status_code=400,
            detail=f"Trading mode '{request.trading_mode}' is not available or not properly configured"
        )
    
    # Additional safety check for live trading
    if request.trading_mode == "live":
        live_account = next((acc for acc in available_accounts.get("available_accounts", []) 
                           if acc["mode"] == "live" and acc["valid"]), None)
        if not live_account:
            raise HTTPException(
                status_code=400,
                detail="Live trading account is not properly configured"
            )
    
    # Update user's trading mode
    await users_collection.update_one(
        {"email": current_user["email"]},
        {"$set": {"trading_mode": request.trading_mode}}
    )
    
    # Log the mode switch with additional details
    await trading_logs_collection.insert_one({
        "user_email": current_user["email"],
        "action": "trading_mode_switch",
        "from_mode": current_user.get("trading_mode", "paper"),
        "to_mode": request.trading_mode,
        "available_modes": valid_modes,
        "timestamp": datetime.utcnow(),
        "ip_address": "unknown",  # Could be enhanced with real IP tracking
        "user_agent": "unknown"   # Could be enhanced with real user agent
    })
    
    return {
        "success": True,
        "message": f"Successfully switched to {request.trading_mode} trading mode",
        "trading_mode": request.trading_mode,
        "previous_mode": current_user.get("trading_mode", "paper")
    }

# API Key Management with Validation
@app.post("/api/keys/add")
async def add_api_key(key_data: APIKeyCreate, current_user: dict = Depends(get_current_user)):
    # Validate the API key before storing
    validation_result = {"valid": False, "message": "Unknown error"}
    
    try:
        if key_data.provider == "alpaca" and key_data.secret_key:
            # Validate Alpaca API keys
            base_url = "https://paper-api.alpaca.markets" if key_data.environment == "paper" else "https://api.alpaca.markets"
            alpaca_client = AlpacaClient(key_data.api_key, key_data.secret_key, base_url)
            is_valid, message = alpaca_client.validate_connection()
            validation_result = {"valid": is_valid, "message": message}
            
        elif key_data.provider == "finnhub":
            # Validate Finnhub API key
            finnhub_client = FinnhubClient(key_data.api_key)
            test_quote = await finnhub_client.get_quote("AAPL")
            if test_quote and 'c' in test_quote:
                validation_result = {"valid": True, "message": "Finnhub API key validated successfully"}
            else:
                validation_result = {"valid": False, "message": "Finnhub API key validation failed"}
                
        elif key_data.provider == "coingecko":
            # Validate CoinGecko API key
            coingecko_client = CoinGeckoClient(key_data.api_key)
            test_data = coingecko_client.get_price(["bitcoin"], "usd")
            if test_data and "bitcoin" in test_data:
                validation_result = {"valid": True, "message": "CoinGecko API key validated successfully"}
            else:
                validation_result = {"valid": False, "message": "CoinGecko API key validation failed"}
                
    except Exception as e:
        validation_result = {"valid": False, "message": f"Validation error: {str(e)}"}
    
    # Only store if validation passes or user explicitly wants to store invalid keys
    if not validation_result["valid"]:
        return {
            "success": False,
            "validation": validation_result,
            "message": "API key validation failed. Please check your credentials."
        }
    
    # Encrypt the API key before storing
    encrypted_key = encrypt_api_key(key_data.api_key)
    encrypted_secret = encrypt_api_key(key_data.secret_key) if key_data.secret_key else None
    
    api_key_doc = {
        "id": str(uuid.uuid4()),
        "user_email": current_user["email"],
        "provider": key_data.provider,
        "encrypted_api_key": encrypted_key,
        "encrypted_secret_key": encrypted_secret,
        "environment": key_data.environment,
        "created_at": datetime.utcnow(),
        "is_active": True,
        "validation_status": validation_result["valid"],
        "last_validated": datetime.utcnow()
    }
    
    # Remove any existing key for this provider/environment combination
    await api_keys_collection.delete_many({
        "user_email": current_user["email"],
        "provider": key_data.provider,
        "environment": key_data.environment
    })
    
    await api_keys_collection.insert_one(api_key_doc)
    
    # Log the key addition
    await trading_logs_collection.insert_one({
        "user_email": current_user["email"],
        "action": "api_key_added",
        "provider": key_data.provider,
        "environment": key_data.environment,
        "validation_status": validation_result["valid"],
        "timestamp": datetime.utcnow()
    })
    
    return {
        "success": True,
        "validation": validation_result,
        "message": f"API key for {key_data.provider} ({key_data.environment}) added successfully"
    }

@app.post("/api/keys/validate/{key_id}")
async def validate_api_key(key_id: str, current_user: dict = Depends(get_current_user)):
    # Get the API key from database
    key_doc = await api_keys_collection.find_one({
        "id": key_id,
        "user_email": current_user["email"],
        "is_active": True
    })
    
    if not key_doc:
        raise HTTPException(status_code=404, detail="API key not found")
    
    # Decrypt and validate
    api_key = decrypt_api_key(key_doc["encrypted_api_key"])
    secret_key = decrypt_api_key(key_doc["encrypted_secret_key"]) if key_doc.get("encrypted_secret_key") else None
    
    validation_result = {"valid": False, "message": "Unknown error"}
    
    try:
        if key_doc["provider"] == "alpaca" and secret_key:
            base_url = "https://paper-api.alpaca.markets" if key_doc["environment"] == "paper" else "https://api.alpaca.markets"
            alpaca_client = AlpacaClient(api_key, secret_key, base_url)
            is_valid, message = alpaca_client.validate_connection()
            validation_result = {"valid": is_valid, "message": message}
            
        elif key_doc["provider"] == "finnhub":
            finnhub_client = FinnhubClient(api_key)
            test_quote = await finnhub_client.get_quote("AAPL")
            if test_quote and 'c' in test_quote:
                validation_result = {"valid": True, "message": "Finnhub API key is working"}
            else:
                validation_result = {"valid": False, "message": "Finnhub API key validation failed"}
                
    except Exception as e:
        validation_result = {"valid": False, "message": f"Validation error: {str(e)}"}
    
    # Update validation status
    await api_keys_collection.update_one(
        {"id": key_id},
        {
            "$set": {
                "validation_status": validation_result["valid"],
                "last_validated": datetime.utcnow()
            }
        }
    )
    
    return validation_result

@app.get("/api/keys/list")
async def list_api_keys(current_user: dict = Depends(get_current_user)):
    keys = await api_keys_collection.find({
        "user_email": current_user["email"],
        "is_active": True
    }).to_list(100)
    
    # Return only non-sensitive information
    return [{
        "id": key["id"],
        "provider": key["provider"],
        "environment": key["environment"],
        "created_at": key["created_at"]
    } for key in keys]

@app.delete("/api/keys/{key_id}")
async def delete_api_key(key_id: str, current_user: dict = Depends(get_current_user)):
    result = await api_keys_collection.update_one(
        {"id": key_id, "user_email": current_user["email"]},
        {"$set": {"is_active": False, "deleted_at": datetime.utcnow()}}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="API key not found")
    
    return {"message": "API key deleted successfully"}

async def get_user_api_key(user: dict, provider: str, environment: str = "paper") -> Optional[str]:
    key_doc = await api_keys_collection.find_one({
        "user_email": user["email"],
        "provider": provider,
        "environment": environment,
        "is_active": True
    })
    
    if not key_doc:
        return None
    
    return decrypt_api_key(key_doc["encrypted_api_key"])

# Stock Market Data Routes
@app.get("/api/stocks/quote/{symbol}")
async def get_stock_quote(symbol: str, current_user: dict = Depends(get_current_user)):
    # Get user's Finnhub API key
    api_key = await get_user_api_key(current_user, "finnhub")
    if not api_key:
        # Use default Finnhub key for demo
        api_key = "d1hp2hpr01qsvr2bhr1gd1hp2hpr01qsvr2bhr20"
    
    finnhub_client = FinnhubClient(api_key)
    
    try:
        quote_data = await finnhub_client.get_quote(symbol.upper())
        company_data = await finnhub_client.get_company_profile(symbol.upper())
        
        if not quote_data or 'c' not in quote_data:
            raise HTTPException(status_code=404, detail="Stock symbol not found")
        
        return {
            "symbol": symbol.upper(),
            "current_price": quote_data.get('c', 0),
            "change": quote_data.get('d', 0),
            "change_percent": quote_data.get('dp', 0),
            "high": quote_data.get('h', 0),
            "low": quote_data.get('l', 0),
            "open": quote_data.get('o', 0),
            "previous_close": quote_data.get('pc', 0),
            "volume": company_data.get('shareOutstanding', 0),
            "company_name": company_data.get('name', symbol.upper()),
            "market_cap": company_data.get('marketCapitalization', 0),
            "timestamp": datetime.utcnow()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching stock data: {str(e)}")

@app.get("/api/stocks/search")
async def search_stocks(q: str, current_user: dict = Depends(get_current_user)):
    if len(q) < 1:
        raise HTTPException(status_code=400, detail="Query must be at least 1 character")
    
    # Get user's Finnhub API key
    api_key = await get_user_api_key(current_user, "finnhub")
    if not api_key:
        # Use default Finnhub key for demo
        api_key = "d1hp2hpr01qsvr2bhr1gd1hp2hpr01qsvr2bhr20"
    
    finnhub_client = FinnhubClient(api_key)
    
    try:
        search_results = await finnhub_client.search_stocks(q)
        
        if not search_results or 'result' not in search_results:
            return {"results": []}
        
        results = []
        for result in search_results['result'][:10]:  # Limit to 10 results
            results.append({
                "symbol": result.get('symbol', ''),
                "description": result.get('description', ''),
                "type": result.get('type', ''),
                "displaySymbol": result.get('displaySymbol', '')
            })
        
        return {"results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error searching stocks: {str(e)}")

# Watchlist Management
@app.post("/api/watchlists")
async def create_watchlist(watchlist: WatchlistCreate, current_user: dict = Depends(get_current_user)):
    watchlist_doc = {
        "id": str(uuid.uuid4()),
        "user_email": current_user["email"],
        "name": watchlist.name,
        "symbols": watchlist.symbols,
        "description": watchlist.description,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    
    await watchlists_collection.insert_one(watchlist_doc)
    return {"message": "Watchlist created successfully", "id": watchlist_doc["id"]}

@app.get("/api/watchlists")
async def get_watchlists(current_user: dict = Depends(get_current_user)):
    watchlists = await watchlists_collection.find({
        "user_email": current_user["email"]
    }).to_list(100)
    
    return [
        {
            "id": wl["id"],
            "name": wl["name"],
            "symbols": wl["symbols"],
            "description": wl.get("description", ""),
            "created_at": wl["created_at"],
            "symbol_count": len(wl["symbols"])
        }
        for wl in watchlists
    ]

@app.get("/api/watchlists/{watchlist_id}/quotes")
async def get_watchlist_quotes(watchlist_id: str, current_user: dict = Depends(get_current_user)):
    watchlist = await watchlists_collection.find_one({
        "id": watchlist_id,
        "user_email": current_user["email"]
    })
    
    if not watchlist:
        raise HTTPException(status_code=404, detail="Watchlist not found")
    
    # Get user's Finnhub API key
    api_key = await get_user_api_key(current_user, "finnhub")
    if not api_key:
        # Use default Finnhub key for demo
        api_key = "d1hp2hpr01qsvr2bhr1gd1hp2hpr01qsvr2bhr20"
    
    finnhub_client = FinnhubClient(api_key)
    
    quotes = []
    for symbol in watchlist["symbols"]:
        try:
            quote_data = await finnhub_client.get_quote(symbol)
            if quote_data and 'c' in quote_data:
                quotes.append({
                    "symbol": symbol,
                    "current_price": quote_data.get('c', 0),
                    "change": quote_data.get('d', 0),
                    "change_percent": quote_data.get('dp', 0),
                    "high": quote_data.get('h', 0),
                    "low": quote_data.get('l', 0)
                })
        except Exception as e:
            continue  # Skip failed quotes
    
    return {"watchlist": watchlist["name"], "quotes": quotes}

@app.delete("/api/watchlists/{watchlist_id}")
async def delete_watchlist(watchlist_id: str, current_user: dict = Depends(get_current_user)):
    result = await watchlists_collection.delete_one({
        "id": watchlist_id,
        "user_email": current_user["email"]
    })
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Watchlist not found")
    
    return {"message": "Watchlist deleted successfully"}

# Alpaca Trading Routes
@app.get("/api/trading/account")
async def get_account_info(current_user: dict = Depends(get_current_user)):
    user_trading_mode = current_user.get("trading_mode", "paper")
    
    # Get Alpaca API keys for current trading mode
    alpaca_key = await get_user_api_key(current_user, "alpaca", user_trading_mode)
    alpaca_secret = await get_user_api_key_secret(current_user, "alpaca", user_trading_mode)
    
    if not alpaca_key or not alpaca_secret:
        raise HTTPException(
            status_code=400, 
            detail=f"Alpaca API keys not configured for {user_trading_mode} trading mode"
        )
    
    try:
        base_url = "https://paper-api.alpaca.markets" if user_trading_mode == "paper" else "https://api.alpaca.markets"
        alpaca_client = AlpacaClient(alpaca_key, alpaca_secret, base_url)
        account = alpaca_client.get_account()
        
        return {
            "buying_power": float(account.buying_power),
            "portfolio_value": float(account.portfolio_value),
            "cash": float(account.cash),
            "day_trade_count": account.daytrade_count,
            "trading_mode": user_trading_mode
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching account info: {str(e)}")

@app.get("/api/trading/positions")
async def get_positions(current_user: dict = Depends(get_current_user)):
    user_trading_mode = current_user.get("trading_mode", "paper")
    
    # Get Alpaca API keys
    alpaca_key = await get_user_api_key(current_user, "alpaca", user_trading_mode)
    alpaca_secret = await get_user_api_key_secret(current_user, "alpaca", user_trading_mode)
    
    if not alpaca_key or not alpaca_secret:
        raise HTTPException(
            status_code=400, 
            detail=f"Alpaca API keys not configured for {user_trading_mode} trading mode"
        )
    
    try:
        base_url = "https://paper-api.alpaca.markets" if user_trading_mode == "paper" else "https://api.alpaca.markets"
        alpaca_client = AlpacaClient(alpaca_key, alpaca_secret, base_url)
        positions = alpaca_client.get_positions()
        
        return [{
            "symbol": pos.symbol,
            "quantity": float(pos.qty),
            "market_value": float(pos.market_value),
            "unrealized_pnl": float(pos.unrealized_pl),
            "avg_cost": float(pos.avg_entry_price),
            "current_price": float(pos.current_price) if hasattr(pos, 'current_price') else 0
        } for pos in positions]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching positions: {str(e)}")

@app.post("/api/trading/orders")
async def place_order(order: OrderCreate, current_user: dict = Depends(get_current_user)):
    user_trading_mode = current_user.get("trading_mode", "paper")
    
    # Validate limit order has limit price
    if order.order_type == 'limit' and not order.limit_price:
        raise HTTPException(
            status_code=400, 
            detail="Limit price is required for limit orders"
        )
    
    # Validate limit price is positive
    if order.limit_price and order.limit_price <= 0:
        raise HTTPException(
            status_code=400, 
            detail="Limit price must be greater than 0"
        )
    
    # Safety check for live trading
    if user_trading_mode == "live":
        # Additional confirmation required for live trades
        pass  # In a real implementation, you might want additional safety checks
    
    # Get Alpaca API keys
    alpaca_key = await get_user_api_key(current_user, "alpaca", user_trading_mode)
    alpaca_secret = await get_user_api_key_secret(current_user, "alpaca", user_trading_mode)
    
    if not alpaca_key or not alpaca_secret:
        raise HTTPException(
            status_code=400, 
            detail=f"Alpaca API keys not configured for {user_trading_mode} trading mode"
        )
    
    try:
        base_url = "https://paper-api.alpaca.markets" if user_trading_mode == "paper" else "https://api.alpaca.markets"
        alpaca_client = AlpacaClient(alpaca_key, alpaca_secret, base_url)
        
        # Validate symbol is tradable
        if not alpaca_client.is_tradable(order.symbol):
            raise HTTPException(
                status_code=400,
                detail=f"Symbol {order.symbol} is not supported for trading"
            )
        
        # Place order
        alpaca_order = alpaca_client.place_order(
            symbol=order.symbol,
            qty=order.quantity,
            side=order.side,
            order_type=order.order_type,
            time_in_force='gtc',
            limit_price=order.limit_price
        )
        
        # Log the trade
        await trading_logs_collection.insert_one({
            "user_email": current_user["email"],
            "action": "order_placed",
            "symbol": order.symbol,
            "quantity": order.quantity,
            "side": order.side,
            "order_type": order.order_type,
            "limit_price": order.limit_price,
            "trading_mode": user_trading_mode,
            "alpaca_order_id": alpaca_order.id,
            "timestamp": datetime.utcnow()
        })
        
        return {
            "order_id": alpaca_order.id,
            "status": alpaca_order.status,
            "symbol": alpaca_order.symbol,
            "qty": float(alpaca_order.qty),
            "side": alpaca_order.side,
            "order_type": alpaca_order.order_type,
            "limit_price": float(alpaca_order.limit_price) if hasattr(alpaca_order, 'limit_price') and alpaca_order.limit_price else None,
            "trading_mode": user_trading_mode
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error placing order: {str(e)}")

@app.get("/api/trading/validate-symbol/{symbol}")
async def validate_symbol(symbol: str, current_user: dict = Depends(get_current_user)):
    user_trading_mode = current_user.get("trading_mode", "paper")
    
    # Get Alpaca API keys
    alpaca_key = await get_user_api_key(current_user, "alpaca", user_trading_mode)
    alpaca_secret = await get_user_api_key_secret(current_user, "alpaca", user_trading_mode)
    
    if not alpaca_key or not alpaca_secret:
        return {"tradable": False, "message": "Alpaca API keys not configured"}
    
    try:
        base_url = "https://paper-api.alpaca.markets" if user_trading_mode == "paper" else "https://api.alpaca.markets"
        alpaca_client = AlpacaClient(alpaca_key, alpaca_secret, base_url)
        
        is_tradable = alpaca_client.is_tradable(symbol.upper())
        
        return {
            "symbol": symbol.upper(),
            "tradable": is_tradable,
            "message": "Symbol is tradable" if is_tradable else "This symbol is not supported for trading"
        }
    except Exception as e:
        return {"tradable": False, "message": f"Error validating symbol: {str(e)}"}

@app.get("/api/trading/orders")
async def get_orders(current_user: dict = Depends(get_current_user)):
    user_trading_mode = current_user.get("trading_mode", "paper")
    
    # Get Alpaca API keys
    alpaca_key = await get_user_api_key(current_user, "alpaca", user_trading_mode)
    alpaca_secret = await get_user_api_key_secret(current_user, "alpaca", user_trading_mode)
    
    if not alpaca_key or not alpaca_secret:
        return {"orders": [], "message": "Alpaca API keys not configured"}
    
    try:
        base_url = "https://paper-api.alpaca.markets" if user_trading_mode == "paper" else "https://api.alpaca.markets"
        alpaca_client = AlpacaClient(alpaca_key, alpaca_secret, base_url)
        orders = alpaca_client.get_orders()
        
        order_list = []
        for order in orders[:20]:  # Limit to recent 20 orders
            order_data = {
                "id": order.id,
                "symbol": order.symbol,
                "qty": float(order.qty),
                "side": order.side,
                "order_type": order.order_type,
                "status": order.status,
                "submitted_at": order.submitted_at.isoformat() if order.submitted_at else None,
                "filled_at": order.filled_at.isoformat() if hasattr(order, 'filled_at') and order.filled_at else None,
                "limit_price": None,
                "stop_price": None
            }
            
            # Add limit price if it exists
            if hasattr(order, 'limit_price') and order.limit_price:
                order_data["limit_price"] = float(order.limit_price)
            
            # Add stop price if it exists  
            if hasattr(order, 'stop_price') and order.stop_price:
                order_data["stop_price"] = float(order.stop_price)
                
            order_list.append(order_data)
        
        return {"orders": order_list}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching orders: {str(e)}")
    
@app.get("/api/trading/user-trades/{symbol}")
async def get_user_trades(symbol: str, current_user: dict = Depends(get_current_user)):
    """
    Return all trades for the current user and the given symbol.
    """
    try:
        # Fetch trades from your MongoDB collection
        trades = await trades_collection.find({
            "user_email": current_user["email"],
            "symbol": symbol.upper()
        }).sort("executed_at", -1).to_list(100)

        # Format the trades as a list of dicts (if needed)
        formatted_trades = [
            {
                "symbol": trade.get("symbol"),
                "side": trade.get("side"),
                "quantity": trade.get("quantity"),
                "price": trade.get("price"),
                "order_id": trade.get("order_id"),
                "executed_at": trade.get("executed_at"),
                "trading_mode": trade.get("trading_mode"),
            }
            for trade in trades
        ]

        return {"trades": formatted_trades}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching user trades: {str(e)}")
    
# Data Export Routes
@app.get("/api/export/trading-data")
async def export_trading_data(format: str = "xlsx", current_user: dict = Depends(get_current_user)):
    """Export trading data to Excel or CSV"""
    
    try:
        # Get all trading data for the user
        orders_data = []
        trades_data = []
        
        # Try to get data from both paper and live accounts
        for environment in ["paper", "live"]:
            alpaca_key = await get_user_api_key(current_user, "alpaca", environment)
            alpaca_secret = await get_user_api_key_secret(current_user, "alpaca", environment)
            
            if alpaca_key and alpaca_secret:
                try:
                    base_url = "https://paper-api.alpaca.markets" if environment == "paper" else "https://api.alpaca.markets"
                    alpaca_client = AlpacaClient(alpaca_key, alpaca_secret, base_url)
                    
                    # Get orders
                    orders = alpaca_client.get_orders()
                    for order in orders:
                        orders_data.append({
                            "Account Type": environment.title(),
                            "Order ID": order.id,
                            "Symbol": order.symbol,
                            "Side": order.side.title(),
                            "Quantity": float(order.qty),
                            "Order Type": order.order_type.title(),
                            "Status": order.status.title(),
                            "Limit Price": float(order.limit_price) if hasattr(order, 'limit_price') and order.limit_price else None,
                            "Submitted At": order.submitted_at.isoformat() if order.submitted_at else None,
                            "Filled At": order.filled_at.isoformat() if hasattr(order, 'filled_at') and order.filled_at else None
                        })
                    
                    # Get positions
                    positions = alpaca_client.get_positions()
                    for position in positions:
                        trades_data.append({
                            "Account Type": environment.title(),
                            "Symbol": position.symbol,
                            "Quantity": float(position.qty),
                            "Market Value": float(position.market_value),
                            "Average Entry Price": float(position.avg_entry_price),
                            "Current Price": float(position.current_price) if hasattr(position, 'current_price') else 0,
                            "Unrealized P&L": float(position.unrealized_pl),
                            "Unrealized P&L %": float(position.unrealized_plpc) if hasattr(position, 'unrealized_plpc') else 0,
                            "Day Change": float(position.change_today) if hasattr(position, 'change_today') else 0
                        })
                        
                except Exception as e:
                    continue  # Skip accounts with errors
        
        # Create DataFrame
        import pandas as pd
        from io import BytesIO
        import tempfile
        import os
        
        # Prepare data
        if not orders_data and not trades_data:
            # Return empty data with informational message rather than error
            import pandas as pd
            from io import BytesIO
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if format.lower() == "csv":
                empty_csv = "No trading data available for export.\nTo generate data, please:\n1. Add Alpaca API keys\n2. Place some trades\n3. Try exporting again"
                return Response(
                    content=empty_csv,
                    media_type="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=no_trading_data_{timestamp}.csv"}
                )
            else:
                # Excel with informational message
                output = BytesIO()
                with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                    info_data = {
                        "Status": ["No trading data available"],
                        "Instructions": [
                            "1. Add Alpaca API keys in API Settings",
                            "2. Place some trades in Portfolio & Trading", 
                            "3. Export again to get your trading data"
                        ]
                    }
                    info_df = pd.DataFrame(info_data)
                    info_df.to_excel(writer, sheet_name='Information', index=False)
                
                output.seek(0)
                return Response(
                    content=output.getvalue(),
                    media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": f"attachment; filename=no_trading_data_{timestamp}.xlsx"}
                )
        
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format.lower() == "csv":
            # CSV Export
            output = BytesIO()
            
            if orders_data:
                orders_df = pd.DataFrame(orders_data)
                orders_csv = orders_df.to_csv(index=False)
                
            if trades_data:
                trades_df = pd.DataFrame(trades_data) 
                trades_csv = trades_df.to_csv(index=False)
            
            # Combine both CSVs
            combined_csv = ""
            if orders_data:
                combined_csv += "ORDERS DATA\n" + orders_csv + "\n\n"
            if trades_data:
                combined_csv += "POSITIONS DATA\n" + trades_csv
                
            return Response(
                content=combined_csv,
                media_type="text/csv",
                headers={"Content-Disposition": f"attachment; filename=trading_data_{timestamp}.csv"}
            )
        
        else:
            # Excel Export
            output = BytesIO()
            
            with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                if orders_data:
                    orders_df = pd.DataFrame(orders_data)
                    orders_df.to_excel(writer, sheet_name='Orders', index=False)
                    
                if trades_data:
                    trades_df = pd.DataFrame(trades_data)
                    trades_df.to_excel(writer, sheet_name='Positions', index=False)
                    
                # Add summary sheet
                summary_data = {
                    "Export Details": [
                        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                        f"User: {current_user['email']}",
                        f"Total Orders: {len(orders_data)}",
                        f"Total Positions: {len(trades_data)}",
                        f"Accounts Included: {', '.join(set([item['Account Type'] for item in orders_data + trades_data]))}"
                    ]
                }
                summary_df = pd.DataFrame(summary_data)
                summary_df.to_excel(writer, sheet_name='Summary', index=False)
            
            output.seek(0)
            
            return Response(
                content=output.getvalue(),
                media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                headers={"Content-Disposition": f"attachment; filename=trading_data_{timestamp}.xlsx"}
            )
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Export failed: {str(e)}")

# Enhanced Trading Routes with Price Tracking

# Cryptocurrency Routes
@app.get("/api/crypto/prices")
async def get_crypto_prices(coins: str = "bitcoin,ethereum,cardano,polkadot", current_user: dict = Depends(get_current_user)):
    # Get user's CoinGecko API key if available
    coingecko_key = await get_user_api_key(current_user, "coingecko")
    
    try:
        coingecko_client = CoinGeckoClient(coingecko_key)
        coin_list = coins.split(',')
        prices = coingecko_client.get_price(coin_list, 'usd')
        
        result = []
        for coin_id in coin_list:
            if coin_id in prices:
                coin_data = prices[coin_id]
                result.append({
                    "id": coin_id,
                    "price": coin_data.get('usd', 0),
                    "change_24h": coin_data.get('usd_24h_change', 0)
                })
        
        return {"crypto_prices": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching crypto prices: {str(e)}")

@app.get("/api/crypto/trending")
async def get_trending_crypto(current_user: dict = Depends(get_current_user)):
    # Get user's CoinGecko API key if available
    coingecko_key = await get_user_api_key(current_user, "coingecko")
    
    try:
        coingecko_client = CoinGeckoClient(coingecko_key)
        trending = coingecko_client.get_trending()
        
        return {
            "trending_coins": [{
                "id": coin['item']['id'],
                "name": coin['item']['name'],
                "symbol": coin['item']['symbol'],
                "rank": coin['item']['market_cap_rank']
            } for coin in trending['coins'][:10]]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching trending crypto: {str(e)}")

@app.get("/api/crypto/top")
async def get_top_crypto(limit: int = 10, current_user: dict = Depends(get_current_user)):
    # Get user's CoinGecko API key if available
    coingecko_key = await get_user_api_key(current_user, "coingecko")
    
    try:
        coingecko_client = CoinGeckoClient(coingecko_key)
        top_coins = coingecko_client.get_top_coins(limit)
        
        return {
            "top_coins": [{
                "id": coin['id'],
                "name": coin['name'],
                "symbol": coin['symbol'],
                "current_price": coin['current_price'],
                "market_cap": coin['market_cap'],
                "price_change_24h": coin['price_change_percentage_24h'],
                "rank": coin['market_cap_rank']
            } for coin in top_coins]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching top crypto: {str(e)}")

async def get_user_api_key_secret(user: dict, provider: str, environment: str = "paper") -> Optional[str]:
    """Helper function to get encrypted secret key"""
    key_doc = await api_keys_collection.find_one({
        "user_email": user["email"],
        "provider": provider,
        "environment": environment,
        "is_active": True
    })
    
    if not key_doc or not key_doc.get("encrypted_secret_key"):
        return None
    
    return decrypt_api_key(key_doc["encrypted_secret_key"])

# Notes Management Routes
@app.get("/api/notes")
async def get_notes(current_user: dict = Depends(get_current_user)):
    notes = await notes_collection.find({
        "user_email": current_user["email"]
    }).sort("created_at", -1).to_list(100)
    
    return [{
        "id": note["id"],
        "title": note["title"],
        "content": note["content"],
        "tags": note.get("tags", []),
        "created_at": note["created_at"],
        "updated_at": note.get("updated_at", note["created_at"])
    } for note in notes]

@app.post("/api/notes")
async def create_note(note: NoteCreate, current_user: dict = Depends(get_current_user)):
    note_doc = {
        "id": str(uuid.uuid4()),
        "user_email": current_user["email"],
        "title": note.title,
        "content": note.content,
        "tags": note.tags or [],
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    
    await notes_collection.insert_one(note_doc)
    return {"message": "Note created successfully", "id": note_doc["id"]}

@app.put("/api/notes/{note_id}")
async def update_note(note_id: str, note_update: NoteUpdate, current_user: dict = Depends(get_current_user)):
    update_data = {"updated_at": datetime.utcnow()}
    
    if note_update.title is not None:
        update_data["title"] = note_update.title
    if note_update.content is not None:
        update_data["content"] = note_update.content
    if note_update.tags is not None:
        update_data["tags"] = note_update.tags
    
    result = await notes_collection.update_one(
        {"id": note_id, "user_email": current_user["email"]},
        {"$set": update_data}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Note not found")
    
    return {"message": "Note updated successfully"}

@app.delete("/api/notes/{note_id}")
async def delete_note(note_id: str, current_user: dict = Depends(get_current_user)):
    result = await notes_collection.delete_one({
        "id": note_id,
        "user_email": current_user["email"]
    })
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Note not found")
    
    return {"message": "Note deleted successfully"}

# News Management Routes
@app.get("/api/news/market")
async def get_market_news(category: str = "general", current_user: dict = Depends(get_current_user)):
    # Get user's Finnhub API key
    finnhub_key = await get_user_api_key(current_user, "finnhub")
    if not finnhub_key:
        # Use default Finnhub key for demo
        finnhub_key = "d1hp2hpr01qsvr2bhr1gd1hp2hpr01qsvr2bhr20"
    
    finnhub_client = FinnhubClient(finnhub_key)
    
    try:
        news_data = await finnhub_client.get_market_news(category)
        
        # Store news in database for future AI analysis
        for article in news_data[:10]:  # Store top 10 articles
            await news_collection.update_one(
                {"url": article.get("url")},
                {
                    "$set": {
                        "headline": article.get("headline"),
                        "summary": article.get("summary"),
                        "source": article.get("source"),
                        "category": category,
                        "datetime": datetime.fromtimestamp(article.get("datetime", 0)),
                        "url": article.get("url"),
                        "image": article.get("image"),
                        "related_symbols": article.get("related", []),
                        "sentiment": None,  # To be filled by AI later
                        "created_at": datetime.utcnow()
                    }
                },
                upsert=True
            )
        
        return {"news": news_data[:20]}  # Return top 20 articles
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching market news: {str(e)}")

@app.get("/api/news/company/{symbol}")
async def get_company_news(symbol: str, current_user: dict = Depends(get_current_user)):
    # Get user's Finnhub API key
    finnhub_key = await get_user_api_key(current_user, "finnhub")
    if not finnhub_key:
        # Use default Finnhub key for demo
        finnhub_key = "d1hp2hpr01qsvr2bhr1gd1hp2hpr01qsvr2bhr20"
    
    finnhub_client = FinnhubClient(finnhub_key)
    
    try:
        # Get news for the last 30 days
        to_date = datetime.now().strftime("%Y-%m-%d")
        from_date = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")
        
        news_data = await finnhub_client.get_company_news(symbol.upper(), from_date, to_date)
        
        # Store company news in database
        for article in news_data[:10]:
            await news_collection.update_one(
                {"url": article.get("url")},
                {
                    "$set": {
                        "headline": article.get("headline"),
                        "summary": article.get("summary"),
                        "source": article.get("source"),
                        "category": "company",
                        "primary_symbol": symbol.upper(),
                        "datetime": datetime.fromtimestamp(article.get("datetime", 0)),
                        "url": article.get("url"),
                        "image": article.get("image"),
                        "related_symbols": [symbol.upper()],
                        "sentiment": None,  # To be filled by AI later
                        "created_at": datetime.utcnow()
                    }
                },
                upsert=True
            )
        
        return {"news": news_data[:20], "symbol": symbol.upper()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching company news: {str(e)}")

@app.get("/api/news/watchlist")
async def get_watchlist_news(current_user: dict = Depends(get_current_user)):
    # Get user's watchlists
    watchlists = await watchlists_collection.find({
        "user_email": current_user["email"]
    }).to_list(10)
    
    if not watchlists:
        return {"news": [], "message": "No watchlists found"}
    
    # Collect all symbols from watchlists
    all_symbols = set()
    for watchlist in watchlists:
        all_symbols.update(watchlist.get("symbols", []))
    
    # Get news for each symbol
    finnhub_key = await get_user_api_key(current_user, "finnhub")
    if not finnhub_key:
        finnhub_key = "d1hp2hpr01qsvr2bhr1gd1hp2hpr01qsvr2bhr20"
    
    finnhub_client = FinnhubClient(finnhub_key)
    all_news = []
    
    try:
        to_date = datetime.now().strftime("%Y-%m-%d")
        from_date = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")
        
        for symbol in list(all_symbols)[:5]:  # Limit to 5 symbols to avoid rate limits
            try:
                news_data = await finnhub_client.get_company_news(symbol, from_date, to_date)
                for article in news_data[:3]:  # Top 3 articles per symbol
                    article['primary_symbol'] = symbol
                    all_news.append(article)
            except Exception as e:
                continue  # Skip failed symbols
        
        # Sort by datetime descending
        all_news.sort(key=lambda x: x.get('datetime', 0), reverse=True)
        
        return {"news": all_news[:20], "symbols": list(all_symbols)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching watchlist news: {str(e)}")

@app.post("/api/news/search")
async def search_news(search_request: NewsSearch, current_user: dict = Depends(get_current_user)):
    try:
        # Search in stored news first
        query_filter = {}
        
        if search_request.query:
            query_filter["$or"] = [
                {"headline": {"$regex": search_request.query, "$options": "i"}},
                {"summary": {"$regex": search_request.query, "$options": "i"}}
            ]
        
        if search_request.symbols:
            query_filter["related_symbols"] = {"$in": [s.upper() for s in search_request.symbols]}
        
        if search_request.category != "general":
            query_filter["category"] = search_request.category
        
        # Get stored news
        stored_news = await news_collection.find(query_filter).sort("datetime", -1).limit(20).to_list(20)
        
        # Also get fresh market news if no specific search
        fresh_news = []
        if not search_request.query and not search_request.symbols:
            finnhub_key = await get_user_api_key(current_user, "finnhub")
            if not finnhub_key:
                finnhub_key = "d1hp2hpr01qsvr2bhr1gd1hp2hpr01qsvr2bhr20"
            
            finnhub_client = FinnhubClient(finnhub_key)
            fresh_market_news = await finnhub_client.get_market_news(search_request.category)
            fresh_news = fresh_market_news[:10]
        
        # Combine and format results
        all_results = []
        
        # Add stored news
        for news in stored_news:
            all_results.append({
                "headline": news.get("headline"),
                "summary": news.get("summary"),
                "source": news.get("source"),
                "datetime": news.get("datetime").timestamp() if news.get("datetime") else 0,
                "url": news.get("url"),
                "image": news.get("image"),
                "related": news.get("related_symbols", []),
                "sentiment": news.get("sentiment")
            })
        
        # Add fresh news
        all_results.extend(fresh_news)
        
        # Remove duplicates and sort by datetime
        seen_urls = set()
        unique_results = []
        for article in all_results:
            if article.get("url") not in seen_urls:
                seen_urls.add(article.get("url"))
                unique_results.append(article)
        
        unique_results.sort(key=lambda x: x.get('datetime', 0), reverse=True)
        
        return {"news": unique_results[:20]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error searching news: {str(e)}")

# Health check
@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow()}

if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.environ.get("PORT", 8001))
    uvicorn.run(app, host="0.0.0.0", port=port)


    