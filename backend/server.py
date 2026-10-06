from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, APIRouter, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List
from datetime import datetime, timezone, timedelta
from pathlib import Path
import os, uuid, bcrypt, jwt, asyncio, logging
import resend
ROOT_DIR = Path(__file__).parent
mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]
app = FastAPI(title="ServiceSync API")
api = APIRouter(prefix="/api")
JWT_SECRET = os.environ["JWT_SECRET"]
STAFF_EMAIL = os.environ["STAFF_EMAIL"].lower()
STAFF_PASSWORD = os.environ["STAFF_PASSWORD"]
STATUSES = ["Pending", "Confirmed", "In Progress", "Completed", "Cancelled"]
resend.api_key = os.environ.get("RESEND_API_KEY", "")
SENDER_EMAIL_FROM = os.environ.get("SENDER_EMAIL", "ServiceSync <onboarding@resend.dev>")
logger = logging.getLogger("servicesync")

async def send_confirmation_email(user_doc, booking_doc, vehicle_doc):
    if not resend.api_key:
        logger.warning("RESEND_API_KEY not set — skipping email")
        return
    to_email = user_doc.get("email")
    if not to_email:
        return
    name = user_doc.get("name", "Customer")
    v = f'{vehicle_doc.get("make","")} {vehicle_doc.get("model","")} · {vehicle_doc.get("registration_number","")}' if vehicle_doc else "your vehicle"
    html = f"""
    <table width="100%" style="font-family:Arial,sans-serif;background:#f4f1fb;padding:24px">
      <tr><td align="center">
        <table width="560" style="background:#ffffff;border-radius:14px;padding:28px">
          <tr><td>
            <p style="color:#6c4bd1;letter-spacing:2px;font-size:12px;margin:0 0 8px">SERVICeSYNC</p>
            <h1 style="margin:0 0 12px;color:#1b1340">Your service is confirmed, {name}.</h1>
            <p style="color:#4a4466;line-height:1.6">We're all set for your upcoming visit:</p>
            <table style="margin:18px 0" cellpadding="8">
              <tr><td style="color:#8a84a3">Service</td><td><strong>{booking_doc.get("service_type","")}</strong></td></tr>
              <tr><td style="color:#8a84a3">Vehicle</td><td><strong>{v}</strong></td></tr>
              <tr><td style="color:#8a84a3">Date</td><td><strong>{booking_doc.get("appointment_date","")}</strong></td></tr>
              <tr><td style="color:#8a84a3">Time</td><td><strong>{booking_doc.get("appointment_time","")}</strong></td></tr>
              <tr><td style="color:#8a84a3">Invoice #</td><td><strong>{booking_doc.get("invoice_number","")}</strong></td></tr>
            </table>
            <p style="color:#4a4466;line-height:1.6">We'll keep you posted as the service progresses.</p>
            <p style="margin-top:28px;color:#8a84a3;font-size:12px">— The ServiceSync Team</p>
          </td></tr>
        </table>
      </td></tr>
    </table>
    """
    try:
        result = await asyncio.to_thread(resend.Emails.send, {
            "from": SENDER_EMAIL_FROM,
            "to": [to_email],
            "subject": f"Confirmed: {booking_doc.get('service_type','Service')} on {booking_doc.get('appointment_date','')}",
            "html": html,
        })
        logger.info(f"Confirmation email sent to {to_email}: {result.get('id')}")
    except Exception as e:
        logger.error(f"Failed to send confirmation email: {e}")
class AuthInput(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6)

class RegisterInput(AuthInput):
    name: str = Field(min_length=2)
    phone: str = ""

class VehicleInput(BaseModel):
    make: str
    model: str
    year: str
    registration_number: str
    notes: str = ""

class BookingInput(BaseModel):
    vehicle_id: str
    service_type: str
    appointment_date: str
    appointment_time: str
    notes: str = ""

class BookingUpdate(BaseModel):
    status: Optional[str] = None
    price: Optional[float] = None
    payment_status: Optional[str] = None
    staff_note: Optional[str] = None

class ProfileInput(BaseModel):
    name: str
    phone: str = ""
    address: str = ""

class ReviewInput(BaseModel):
    booking_id: str
    rating: int = Field(ge=1, le=5)
    comment: str = Field(min_length=2)

def now():
    return datetime.now(timezone.utc).isoformat()

def safe_user(doc):
    if not doc: return None
    return {"id": doc["id"], "name": doc.get("name", ""), "email": doc["email"], "phone": doc.get("phone", ""), "address": doc.get("address", ""), "role": doc.get("role", "user"), "created_at": doc.get("created_at")}

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())

def token_for(user):
    return jwt.encode({"sub": user["id"], "exp": datetime.now(timezone.utc) + timedelta(days=7)}, JWT_SECRET, algorithm="HS256")

async def current_user(authorization: Optional[str] = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Please log in to continue")
    try:
        payload = jwt.decode(authorization[7:], JWT_SECRET, algorithms=["HS256"])
        user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0})
        if not user: raise HTTPException(401, "Account not found")
        return user
    except jwt.PyJWTError:
        raise HTTPException(401, "Session expired")

async def staff_only(user=Depends(current_user)):
    if user.get("role") != "staff": raise HTTPException(403, "Staff access required")
    return user

async def seed_staff():
    existing = await db.users.find_one({"email": STAFF_EMAIL})
    if not existing:
        await db.users.insert_one({"id": str(uuid.uuid4()), "name": "ServiceSync Staff", "email": STAFF_EMAIL, "password_hash": hash_password(STAFF_PASSWORD), "phone": "", "address": "", "role": "staff", "created_at": now()})
    elif not verify_password(STAFF_PASSWORD, existing["password_hash"]):
        await db.users.update_one({"email": STAFF_EMAIL}, {"$set": {"password_hash": hash_password(STAFF_PASSWORD)}})
    await db.users.create_index("email", unique=True)
    await db.login_attempts.create_index("identifier", unique=True)

@app.on_event("startup")
async def startup():
    await seed_staff()

@api.get("/")
async def root(): return {"message": "ServiceSync API online"}

@api.post("/auth/register")
async def register(data: RegisterInput):
    email = data.email.lower()
    if await db.users.find_one({"email": email}): raise HTTPException(400, "An account with this email already exists")
    user = {"id": str(uuid.uuid4()), "name": data.name, "email": email, "password_hash": hash_password(data.password), "phone": data.phone, "address": "", "role": "user", "created_at": now()}
    await db.users.insert_one(user)
    return {"user": safe_user(user), "token": token_for(user)}

@api.post("/auth/login")
async def login(data: AuthInput):
    email = data.email.lower()
    identifier = email
    attempt = await db.login_attempts.find_one({"identifier": identifier}, {"_id": 0})
    if attempt and attempt.get("locked_until") and attempt["locked_until"] > now():
        raise HTTPException(429, "Too many attempts. Please try again in 15 minutes")
    user = await db.users.find_one({"email": email})
    if not user or not verify_password(data.password, user["password_hash"]):
        count = (attempt or {}).get("count", 0) + 1
        values = {"count": count, "last_attempt": now()}
        if count >= 5: values["locked_until"] = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
        await db.login_attempts.update_one({"identifier": identifier}, {"$set": values}, upsert=True)
        raise HTTPException(401, "Email or password is incorrect")
    await db.login_attempts.delete_one({"identifier": identifier})
    return {"user": safe_user(user), "token": token_for(user)}

@api.get("/auth/me")
async def me(user=Depends(current_user)): return safe_user(user)

@api.put("/profile")
async def update_profile(data: ProfileInput, user=Depends(current_user)):
    await db.users.update_one({"id": user["id"]}, {"$set": data.model_dump()})
    return safe_user(await db.users.find_one({"id": user["id"]}, {"_id": 0}))

@api.get("/vehicles")
async def vehicles(user=Depends(current_user)):
    return await db.vehicles.find({"user_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(100)

@api.post("/vehicles")
async def add_vehicle(data: VehicleInput, user=Depends(current_user)):
    doc = {"id": str(uuid.uuid4()), "user_id": user["id"], **data.model_dump(), "created_at": now()}
    await db.vehicles.insert_one(doc); return {k:v for k,v in doc.items() if k != "_id"}

@api.put("/vehicles/{vehicle_id}")
async def edit_vehicle(vehicle_id: str, data: VehicleInput, user=Depends(current_user)):
    result = await db.vehicles.update_one({"id": vehicle_id, "user_id": user["id"]}, {"$set": data.model_dump()})
    if not result.matched_count: raise HTTPException(404, "Vehicle not found")
    return await db.vehicles.find_one({"id": vehicle_id}, {"_id": 0})

@api.delete("/vehicles/{vehicle_id}")
async def delete_vehicle(vehicle_id: str, user=Depends(current_user)):
    result = await db.vehicles.delete_one({"id": vehicle_id, "user_id": user["id"]})
    if not result.deleted_count: raise HTTPException(404, "Vehicle not found")
    return {"ok": True}

@api.get("/bookings")
async def bookings(user=Depends(current_user)):
    query = {} if user.get("role") == "staff" else {"user_id": user["id"]}
    items = await db.bookings.find(query, {"_id": 0}).sort("appointment_date", -1).to_list(500)
    for item in items:
        owner = await db.users.find_one({"id": item["user_id"]}, {"_id": 0, "name": 1, "email": 1, "phone": 1})
        item["customer"] = owner or {}
        vehicle = await db.vehicles.find_one({"id": item["vehicle_id"]}, {"_id": 0})
        item["vehicle"] = vehicle or {}
    return items

@api.post("/bookings")
async def create_booking(data: BookingInput, user=Depends(current_user)):
    vehicle = await db.vehicles.find_one({"id": data.vehicle_id, "user_id": user["id"]})
    if not vehicle: raise HTTPException(400, "Choose one of your vehicles")
    doc = {"id": str(uuid.uuid4()), "user_id": user["id"], **data.model_dump(), "status": "Pending", "price": 0, "payment_status": "Unpaid", "invoice_number": "INV-" + str(uuid.uuid4())[:8].upper(), "staff_note": "", "created_at": now()}
    await db.bookings.insert_one(doc); return {k:v for k,v in doc.items() if k != "_id"}

@api.patch("/bookings/{booking_id}")
async def update_booking(booking_id: str, data: BookingUpdate, user=Depends(staff_only)):
    values = {k:v for k,v in data.model_dump().items() if v is not None}
    if values.get("status") and values["status"] not in STATUSES: raise HTTPException(400, "Invalid status")
    prev = await db.bookings.find_one({"id": booking_id})
    if not prev: raise HTTPException(404, "Booking not found")
    await db.bookings.update_one({"id": booking_id}, {"$set": values})
    item = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    if values.get("status") == "Confirmed" and prev.get("status") != "Confirmed":
        customer = await db.users.find_one({"id": item["user_id"]})
        vehicle = await db.vehicles.find_one({"id": item.get("vehicle_id")})
        asyncio.create_task(send_confirmation_email(customer or {}, item, vehicle or {}))
    return item

@api.get("/reviews")
async def reviews(): return await db.reviews.find({}, {"_id": 0}).sort("created_at", -1).to_list(100)

@api.post("/reviews")
async def create_review(data: ReviewInput, user=Depends(current_user)):
    booking = await db.bookings.find_one({"id": data.booking_id, "user_id": user["id"], "status": "Completed"})
    if not booking: raise HTTPException(400, "Reviews are available after a completed service")
    if await db.reviews.find_one({"booking_id": data.booking_id}): raise HTTPException(400, "You already reviewed this service")
    doc = {"id": str(uuid.uuid4()), "booking_id": data.booking_id, "user_id": user["id"], "customer_name": user.get("name", "Customer"), **data.model_dump(exclude={"booking_id"}), "created_at": now()}
    await db.reviews.insert_one(doc); return {k:v for k,v in doc.items() if k != "_id"}

app.include_router(api)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False, allow_methods=["*"], allow_headers=["*"])

@app.on_event("shutdown")
async def shutdown(): client.close()