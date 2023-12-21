from sqlalchemy import Column, Integer, String
from database import Base


class OTPSend(Base):
    __tablename__ = "OTPs"
    id = Column(Integer, primary_key=True, index=True)
    Phone_Number = Column(String(10))
    OTP = Column(String(10))
    Verification = Column(String(15))


class Register(Base):
    __tablename__ = "Registration"

    Name = Column(String(50))
    Email_id = Column(String(30), primary_key=True, index=True)
    password = Column(String(225))
    Phone_Number = Column(String(10))


class Login(Base):
    __tablename__ = "Login"

    Email_id = Column(String(30), primary_key=True, index=True)
    password = Column(String(225))
    Token = Column(String(500))
