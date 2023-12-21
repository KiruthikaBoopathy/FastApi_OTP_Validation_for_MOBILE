import datetime

from fastapi import FastAPI, HTTPException, Depends, Body
from starlette import status
from twilio.rest import Client
from pydantic import BaseModel
from sqlalchemy.orm import Session
import models
import schemas
import random
from models import Register, OTPSend
from Authentication import hash_pass, authenticate_user, create_access_token, decode_token
from database import engine, SessionLocal

app = FastAPI()

models.Base.metadata.create_all(bind=engine)


def get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()


TWILIO_ACCOUNT_SID = 'AC22cf3bc02e219979051968909d18e67c'
TWILIO_AUTH_TOKEN = '556f77845df5bd0256a75565a10499b4'
TWILIO_PHONE_NUMBER = '+12059272287'

client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)


def generate_otp() -> str:
    return str(random.randint(10000, 99999))


@app.post("/otp_request", tags=["OTP_send_validation"])
def send_otp(otp_request: schemas.OTPRequest, db: Session = Depends(get_db)):
    mobile_number = otp_request.Phone_Number
    formatted_mobile_number = '+91' + ''.join(filter(str.isdigit, mobile_number))
    otp = generate_otp()
    message = client.messages.create(
        body=f'Your updated OTP is: {otp}',
        from_=TWILIO_PHONE_NUMBER,
        to=formatted_mobile_number
    )

    existing_otp_info = db.query(models.OTPSend).filter(models.OTPSend.Phone_Number == mobile_number).first()

    if existing_otp_info:
        existing_otp_info.OTP = otp
        db.commit()
        response = {"message": "OTP updated successfully", "otp": otp, "twilio_response": message.sid}

    else:
        otp_info = models.OTPSend(Phone_Number=mobile_number, OTP=otp, Verification="Invalid")
        db.add(otp_info)
        db.commit()
        response = {"message": "OTP sent successfully", "otp": otp, "twilio_response": message.sid}

    return response


@app.post("/otp_validation_request",tags=["OTP_send_validation"])
def verify_otp(otp_validation_request: schemas.OTPVerificationRequest, db: Session = Depends(get_db)):
    entered_otp = otp_validation_request.otp
    mobile_number = otp_validation_request.Phone_Number

    # Retrieve OTP information from the database
    otp_info = db.query(models.OTPSend).filter(models.OTPSend.Phone_Number == mobile_number).first()

    if entered_otp == otp_info.OTP:
        otp_info.Verification = "Valid"
        db.commit()
        return {"message": "OTP verification successful"}
    else:
        raise HTTPException(status_code=401, detail="Invalid OTP")


@app.post("/Registration_Request",tags=["Registration"])
def UserRegistration(Registration_Request: schemas.CreateRegistration, db: Session = Depends(get_db)):
    mobile_number = Registration_Request.Phone_Number
    user_name = Registration_Request.Name
    otp_info = db.query(models.OTPSend).filter(models.OTPSend.Phone_Number == mobile_number).first()
    if otp_info.Verification == "Valid":
        existing_user = db.query(models.Register).filter(models.Register.Name == user_name).first()
        if existing_user:
            response = "user name already taken"
        else:
            hashed_pass = hash_pass(Registration_Request.password)
            Registration_Request.password = hashed_pass
            new_user = models.Register(**Registration_Request.dict())
            db.add(new_user)
            db.commit()
            db.refresh(new_user)
            response = new_user
    return response


@app.post('/Login',tags=["Login_Logout"])
def login_for_access_token(form_data: schemas.User_login, db: Session = Depends(get_db)):
    user = authenticate_user(form_data.Email_id, form_data.password, db)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials", )

    access_token_expires = datetime.timedelta(days=365000)
    access_token = create_access_token(data={"sub": user.Email_id}, expires_delta=access_token_expires)
    login_info = models.Login(Email_id=user.Email_id, password=user.password, Token=access_token)
    db.add(login_info)
    db.commit()
    return {"token_type": "bearer", "access_token": access_token}


@app.post('/Protection_check', tags=["Login"])
def protected_route(decoded_token: dict = Depends(decode_token)):
    return {"message": "This is a protected route", "decoded_token": decoded_token}


@app.post('/Logout', tags=["Logout"])
def logout(logout_request: schemas.LogoutRequest, db: Session = Depends(get_db)):
    user_email = logout_request.email_id
    login_info = db.query(models.Login).filter(models.Login.Email_id == user_email).first()
    if login_info:
        db.delete(login_info)
        db.commit()
        return {"message": "Logout successful"}
