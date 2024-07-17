from sqlalchemy import Column, String, Boolean, Enum
from sqlalchemy.dialects.mysql import INTEGER
from sqlalchemy.orm import relationship
from enum import Enum as PyEnum
from uuid import uuid4
from database import Base

class UserRole(PyEnum):
    admin = "admin"
    user = "user"

class User(Base):
    __tablename__ = "users"

    email = Column(String(255), unique=True, index=True, nullable=False, primary_key=True)
    name = Column(String(255), nullable=False)
    password = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.user)

class SVGFile(Base):
    __tablename__ = "svg_files"

    email = Column(String(255), primary_key=True, nullable=False)
    svg_content = Column(String, nullable=False)

class CountryComment(Base):
    __tablename__ = "country_comments"

    email = Column(String(255), nullable=False, primary_key=True)
    id = Column(String(255), nullable=False, primary_key=True)
    comment = Column(String(255), nullable=True)
