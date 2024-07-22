from fastapi import FastAPI, Depends, HTTPException, status, Request, Response, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from database import SessionLocal, engine, Base
from models import User, SVGFile, CountryComment
from schemas import UserCreate, UserLogin, UserUpdate, User as UserSchema, SVGFile as SVGFileSchema, \
    CountryColorUpdateWithToken, CountryCommentWithToken, OAuth2LoginRequest, CommentUpdateRequest, CommentRequest
from auth import get_user_by_token, pwd_context, authenticate_user, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES, \
    get_current_active_admin
from typing import Optional, List
from datetime import timedelta
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, EmailStr, constr, validator
from SERVER_URL import front, domen
import re
from lxml import etree

Base.metadata.create_all(bind=engine)

app = FastAPI()

origins = [
    domen,
    front,
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class OAuth2PasswordBearerWithCookie(OAuth2PasswordBearer):
    async def __call__(self, request: Request) -> Optional[str]:
        authorization: str = request.cookies.get("Authorization")
        if not authorization:
            return None
        scheme, _, param = authorization.partition(" ")
        return param


oauth2_scheme = OAuth2PasswordBearerWithCookie(tokenUrl="token")


@app.middleware("http")
async def redirect_to_https(request: Request, call_next):
    if request.url.scheme == "http":
        return Response(status_code=status.HTTP_301_MOVED_PERMANENTLY,
                        headers={"Location": request.url.replace(scheme="https")})
    response = await call_next(request)
    return response


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.post("/register/", response_model=dict)
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(
            status_code=400,
            detail="Email already registered",
        )
    hashed_password = pwd_context.hash(user.password)
    new_user = User(email=user.email, name=user.name, password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    with open('/var/www/u2520382/data/back/world-map.svg', 'r') as svg_file:
        svg_content = svg_file.read()
    new_svg_file = SVGFile(email=user.email, svg_content=svg_content)
    db.add(new_svg_file)
    db.commit()

    access_token = create_access_token(data={"sub": user.email})
    response = JSONResponse(content={"access_token": access_token})
    response.set_cookie(key="Authorization", value=f"Bearer {access_token}", httponly=True)
    return response


@app.post("/login", response_model=dict)
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = authenticate_user(db, user.email, user.password)
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": db_user.email}, expires_delta=access_token_expires
    )
    response = JSONResponse(content={"access_token": access_token})
    response.set_cookie(key="Authorization", value=f"Bearer {access_token}", httponly=True)
    return response


@app.put("/update_country_color/", response_model=None)
def update_country_color(update: CountryColorUpdateWithToken, db: Session = Depends(get_db)):
    user = get_user_by_token(update.token, db)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    svg_file = db.query(SVGFile).filter(SVGFile.email == user.email).first()
    if not svg_file:
        raise HTTPException(status_code=404, detail="SVG file not found")

    svg_content = svg_file.svg_content
    country_id = update.id
    color = update.color

    if not re.match(r'^#[0-9A-Fa-f]{6}$', color):
        raise HTTPException(status_code=400, detail="Invalid color format. Expected hex color code, e.g., #00FF00")

    try:
        # Преобразование строки SVG в байты
        svg_bytes = svg_content.encode('utf-8')
        root = etree.fromstring(svg_bytes)
    except etree.XMLSyntaxError as e:
        raise HTTPException(status_code=500, detail=f"SVG parsing error: {e}")

    namespace = {'svg': 'http://www.w3.org/2000/svg'}
    path_elements = root.xpath(f'//svg:path[@id="{country_id}"]', namespaces=namespace)

    if not path_elements:
        raise HTTPException(status_code=404, detail=f"Country ID {country_id} not found in SVG content")

    for path in path_elements:
        path.set('fill', color)

    updated_svg_content = etree.tostring(root, encoding='unicode')
    svg_file.svg_content = updated_svg_content
    db.commit()
    return {"detail": "Country color updated successfully"}


@app.put("/update_country_comment/", response_model=None)
async def update_country_comment(request: CommentUpdateRequest, db: Session = Depends(get_db)):
    user = get_user_by_token(request.token, db)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    country_comment = db.query(CountryComment).filter(CountryComment.email == user.email,
                                                      CountryComment.id == request.id).first()
    if country_comment is None:
        country_comment = CountryComment(email=user.email, id=request.id, comment=request.comment)
        db.add(country_comment)
    else:
        country_comment.comment = request.comment

    db.commit()
    return {"detail": "Comment updated successfully"}


@app.get("/users/me/", response_model=UserSchema)
def read_users_me(current_user: User = Depends(get_current_active_admin)):
    return current_user


@app.put("/update_user/{user_id}/", response_model=None)
def update_user(user_id: int, user: UserUpdate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.name:
        db_user.name = user.name
    if user.email:
        db_user.email = user.email
    if user.password:
        db_user.password = pwd_context.hash(user.password)

    db.commit()
    return {"detail": "User updated successfully"}


@app.get("/get_svg_content/", response_model=None)
def get_svg_content(token: str, db: Session = Depends(get_db)):
    user = get_user_by_token(token, db)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    svg_file = db.query(SVGFile).filter(SVGFile.email == user.email).first()
    if not svg_file:
        raise HTTPException(status_code=404, detail="SVG file not found")

    return Response(content=svg_file.svg_content, media_type="image/svg+xml")


@app.post("/get_country_comment/", response_model=str)
async def get_country_comment(request: CommentRequest, db: Session = Depends(get_db)):
    user = get_user_by_token(request.token, db)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    country_comment = db.query(CountryComment).filter(CountryComment.email == user.email,
                                                      CountryComment.id == request.id).first()
    if country_comment is None:
        raise HTTPException(status_code=404, detail="Comment not found")

    return country_comment.comment

#
