from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from urllib.parse import quote_plus

username = "root"
password = "vrdella!6"
host = "localhost"
database = "FastApi"

# URL-encode the password
encoded_password = quote_plus(password)

# Create the connection string
DATABASE_URL = f"mysql+mysqlconnector://{username}:{encoded_password}@{host}/{database}"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

