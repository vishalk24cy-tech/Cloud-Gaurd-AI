from pydantic import BaseModel, EmailStr
from typing import Optional


class UserRegister(BaseModel):
    name: str
    email: EmailStr
    password: str
    organization: Optional[str] = None
    invitation_token: Optional[str] = None