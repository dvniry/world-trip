from pydantic import BaseModel, EmailStr, constr, validator 
from typing import Optional
from uuid import UUID
import re

class UserBase(BaseModel):
    name: constr(pattern=r'^[a-zA-Z0-9]+$')
    email: EmailStr

    @validator('name')
    def name_must_be_alphanumeric(cls, v):
        if not re.match(r'^[a-zA-Z0-9]+$', v):
            raise ValueError('Name must contain only letters and numbers')
        return v

class TokenSchema(BaseModel):
    token: str

class TokenData(BaseModel):
    email: str

class CountryColorUpdateWithToken(BaseModel):
    token: str
    id: str
    color: str

class CountryCommentWithToken(BaseModel):
    token: str
    id: str
    comment: str

class OAuth2LoginRequest(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: constr(pattern=r'^[a-zA-Z0-9!@#$%^&*(),.?":{}|<>]+$')

    @validator('password')
    def password_must_be_strong(cls, v):
        if not re.match(r'^[a-zA-Z0-9!@#$%^&*(),.?":{}|<>]+$', v):
            raise ValueError('Password contains invalid characters')
        return v

class User(UserBase):
    id: UUID

    class Config:
        from_attributes = True

class UserCreate(UserBase):
    password: constr(pattern=r'^[a-zA-Z0-9!@#$%^&*(),.?":{}|<>]+$')

    @validator('password')
    def password_must_be_strong(cls, v):
        if not re.match(r'^[a-zA-Z0-9!@#$%^&*(),.?":{}|<>]+$', v):
            raise ValueError('Password contains invalid characters')
        return v

class UserUpdate(UserBase):
    password: Optional[constr(pattern=r'^[a-zA-Z0-9!@#$%^&*(),.?":{}|<>]+$')] = None

    @validator('password', pre=True, always=True)
    def password_must_be_strong(cls, v):
        if v and not re.match(r'^[a-zA-Z0-9!@#$%^&*(),.?":{}|<>]+$', v):
            raise ValueError('Password contains invalid characters')
        return v

class SVGFile(BaseModel):
    email: str
    svg_content: str

class CountryColorUpdate(BaseModel):
    id: str
    color: str

class CommentRequest(BaseModel):
    token: str
    id: str

class CommentUpdateRequest(BaseModel):
    token: str
    id: str
    comment: str