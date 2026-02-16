import os
import random
import bcrypt
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Header, Depends
from jose import jwt
from pydantic import BaseModel
from sqlalchemy import MetaData, create_engine, text
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose.exceptions import JWTError

bearer = HTTPBearer()
load_dotenv()
password = os.getenv("password")
secret = os.getenv("secret")
DATABASE_URL = f"postgresql://postgres:{password}@localhost:5432/prac1"
engine = create_engine(DATABASE_URL, echo=True)
metadata = MetaData()


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class UserRegistration(BaseModel):
    login: str
    password: str
    role: str
    name: str

class UserVerification(BaseModel):
    login: str
    code: int

class UserLogin(BaseModel):
    login : str
    password : str

class Lesson(BaseModel):
    item_id : int
    group_id : int
    date : str
    lesson_number : int

class Grade(BaseModel):
    item_id : int
    group_id : int
    date : str
    lesson_number : int
    grade : int
    student_id : int

@app.post('/reg')
async def registration(user : UserRegistration):
    user.role = user.role.lower()
    if user.role not in ('student', 'teacher', 'admin'):
        return {"status" : "info", "message" : "This role doesn't exist."}
    with engine.connect() as connection:
        sql = text("SELECT * FROM users WHERE login = :login")
        result = connection.execute(sql, {"login" : user.login })
        rows = result.fetchall()
    if rows:
        return {"status" : "info", "message" : "Account with this login already exists."}
    else:

        h = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())
        with engine.connect() as connection:
            h = h.decode('utf-8')
            code = random.randrange(100, 999)
            sql = text("INSERT INTO public.users(login, role, password, code, name) VALUES (:login, :role, :password, :code, :name);")
            result = connection.execute(sql, {"login": user.login, "role" : user.role, "password" : h, "code" : code, "name" : user.name})
            connection.commit()
        return {"status" : "success", "message" : "Account successfully created. Verification required."}
    
@app.post('/login')
async def login(user : UserLogin):
    with engine.connect() as connection:
        sql = text("SELECT * FROM users WHERE login = :login")
        result = connection.execute(sql, {"login" : user.login })
        rows = result.fetchall()
    if rows:
        password = str(rows[0][4]).encode('utf-8')
        if bcrypt.checkpw(user.password.encode('utf-8'), password):
            if (rows[0][3]):
                token = jwt.encode({"id" : rows[0][0]}, secret, algorithm="HS256")
                return {"status" : "success", "message" : "Authorized.", "token" : token}
            else:
                return {"status" : "success", "message" : "Authorized. Not verificated."}
        else:
            return {"status" : "info", "message" : "Wrong password."}
    else:
        return {"status" : "info", "message" : "Account with this login doesn't exist."}
    
@app.post('/verify')
async def verify(user : UserVerification):
    with engine.connect() as connection:
        sql = text("SELECT * FROM users WHERE login = :login")
        result = connection.execute(sql, {"login" : user.login})
        rows = result.fetchall()
    if rows:
        code = rows[0][5]
        if user.code == code:
            with engine.connect() as connection:
                sql = text('UPDATE users SET "isVerified" = TRUE WHERE login = :login')
                result = connection.execute(sql, {"login" : user.login})
                connection.commit()
                token = jwt.encode({"id" : rows[0][0]}, secret, algorithm="HS256")
            return {"status" : "success", "message" : "Account was verificated successfully.", "token" : token}
        else:
            return {"status" : "info", "message" : "Wrong code. Try again."}
    else:
        return {"status" : "info", "message" : "Users not found."}
    
@app.get('/schedule')
async def schedule(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    token = credentials.credentials
    try:
        decoded = jwt.decode(token, secret, algorithms=["HS256"])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    with engine.connect() as connection:
        sql = text("SELECT * FROM schedule")
        result = connection.execute(sql)
        rows = result.fetchall()
    if rows:
        rows = [tuple(r) for r in rows]
        return {"status" : "success", "message" : "Schedule fetched successfully.", "schedule" : rows}
    else:
        return {"status" : "info", "message" : "No schedule found."}

@app.post('/schedule/lesson')
async def grades(lesson : Lesson, credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    token = credentials.credentials
    try:
        decoded = jwt.decode(token, secret, algorithms=["HS256"])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    with engine.connect() as connection:
        sql = text("SELECT * FROM grades WHERE item_id = :item_id and group_id = :group_id and date = :date and lesson_number = :lesson_number")
        result = connection.execute(sql, {"item_id" : lesson.item_id, "group_id" : lesson.group_id, "date" : lesson.date, "lesson_number" : lesson.lesson_number})
        rows = result.fetchall()
    if rows:
        rows = [tuple(r) for r in rows]
        return {"status" : "success", "message" : "Schedule fetched successfully.", "schedule" : rows}
    else:
        return {"status" : "info", "message" : "No schedule found."}

@app.post('/schedule/lesson/grade')
async def set_grade(grade : Grade, credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    token = credentials.credentials
    try:
        decoded = jwt.decode(token, secret, algorithms=["HS256"])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user_id = decoded["id"]
    with engine.connect() as connection:
        sql = text("SELECT * FROM users WHERE id = :id")
        result = connection.execute(sql, {"id" : user_id})
        rows = result.fetchall()
        if rows[0][2] == "student":
            return {"status" : "info", "message" : "You cant do that."}
    with engine.connect() as connection:
        sql = text("INSERT INTO public.grades(grade, student_id, item_id, group_id, date, lesson_number) VALUES (:grade, :student_id, :item_id, :group_id, :date, :lesson_number);")
        result = connection.execute(sql, {"grade" : grade.grade, "student_id" : grade.student_id, "item_id" : grade.item_id, "group_id" : grade.group_id, "date" : grade.date, "lesson_number" : grade.lesson_number})
        connection.commit()
        return {"status" : "success", "message" : "Grade added successfully."}
