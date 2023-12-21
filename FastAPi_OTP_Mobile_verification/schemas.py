from pydantic import BaseModel, Field


class OTPRequest(BaseModel):
    Phone_Number: str = Field(max_length=10)


class OTPVerificationRequest(BaseModel):
    Phone_Number: str = Field(max_length=10)
    otp: str


class CreateRegistration(BaseModel):
    Name: str = Field(max_length=50)
    Email_id: str = Field(max_length=30)
    password: str = Field(max_length=225)
    Phone_Number: str = Field(max_length=10)


class User_login(BaseModel):
    Email_id: str = Field(max_length=30)
    password: str = Field(max_length=225)


class LogoutRequest(BaseModel):
    email_id: str
