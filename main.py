import os
import random
from datetime import date
from typing import Optional
import bcrypt
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.responses import FileResponse
from jose import jwt
from pydantic import BaseModel, Field
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
    identification : Optional[int] = None

class UserVerification(BaseModel):
    login: str
    code: int

class UserLogin(BaseModel):
    login : str
    password : str

class Lesson(BaseModel):
    item_id : int
    group_id : int
    date : date
    lesson_number : int

class SetGrade(BaseModel):
    item_id : int
    group_id : int
    date : date
    lesson_number : int
    grade: int = Field(ge=1, le=5)
    student_id : int

class DelGrade(BaseModel):
    item_id : int
    group_id : int
    date : date
    lesson_number : int
    student_id : int 

class ChangePass(BaseModel):
    login: str
    new_password: str

@app.get("/")
async def index():
    return FileResponse('index_schedule.html')


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
            if user.role != "teacher":
                sql = text("INSERT INTO public.users(login, role, password, code, name) VALUES (:login, :role, :password, :code, :name);")
                result = connection.execute(sql, {"login": user.login, "role" : user.role, "password" : h, "code" : code, "name" : user.name})
            else:
                if user.identification == None:
                    return {"status" : "info", "message" : "No identification given."}
                sql = text("INSERT INTO public.users(login, role, password, code, name, teacher_id) VALUES (:login, :role, :password, :code, :name, :identification);")
                result = connection.execute(sql, {"login": user.login, "role" : user.role, "password" : h, "code" : code, "name" : user.name, "identification" : user.identification})
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
        return {"status" : "success", "message" : "Grades fetched successfully.", "schedule" : rows}
    else:
        return {"status" : "info", "message" : "No schedule found."}

@app.post('/schedule/lesson/set_grade')
async def set_grade(grade : SetGrade, credentials: HTTPAuthorizationCredentials = Depends(bearer)):
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
        if rows[0][2] == "teacher":
            sql = text("SELECT * FROM items WHERE teacher_id = :teacher_id and id = :item_id")
            result = connection.execute(sql, {"teacher_id": rows[0][7], "item_id": grade.item_id})
            rows = result.fetchall()
            if not rows:
                return {"status": "info", "message": "Not your item to deal with grades."}
            sql = text("SELECT * FROM students WHERE id = :student_id AND group_id = :group_id")
            result = connection.execute(sql, {"student_id": grade.student_id, "group_id": grade.group_id})
            student = result.fetchall()
            if not student:
                return {"status": "info", "message": "Student not found in this group."}
        sql = text("INSERT INTO public.grades(grade, student_id, item_id, group_id, date, lesson_number) VALUES (:grade, :student_id, :item_id, :group_id, :date, :lesson_number);")
        result = connection.execute(sql, {"grade" : grade.grade, "student_id" : grade.student_id, "item_id" : grade.item_id, "group_id" : grade.group_id, "date" : grade.date, "lesson_number" : grade.lesson_number})
        connection.commit()
        return {"status" : "success", "message" : "Grade added successfully."}

@app.post('/schedule/lesson/del_grade')
async def del_grade(grade : DelGrade, credentials: HTTPAuthorizationCredentials = Depends(bearer)):
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
        if rows[0][2] == "teacher":
            sql = text("SELECT * FROM items WHERE teacher_id = :teacher_id and id = :item_id")
            result = connection.execute(sql, {"teacher_id": rows[0][7], "item_id": grade.item_id})
            rows = result.fetchall()
            if not rows:
                return {"status": "info", "message": "Not your item to deal with grades."}

            sql = text("SELECT * FROM students WHERE id = :student_id AND group_id = :group_id")
            result = connection.execute(sql, {"student_id": grade.student_id, "group_id": grade.group_id})
            student = result.fetchall()
            if not student:
                return {"status": "info", "message": "Student not found in this group."}  
        sql = text("""SELECT * FROM grades 
                    WHERE item_id = :item_id AND group_id = :group_id 
                    AND lesson_number = :lesson_number AND date = :date 
                    AND student_id = :student_id""")
        result = connection.execute(sql, {
            "item_id": grade.item_id, "group_id": grade.group_id,
            "lesson_number": grade.lesson_number, "date": grade.date,
            "student_id": grade.student_id
        })
        if not result.fetchall():
            return {"status": "info", "message": "Grade not found."}  
        sql = text("DELETE from grades WHERE item_id = :item_id and group_id = :group_id and lesson_number = :lesson_number and date = :date and student_id = :student_id")
        result = connection.execute(sql, {"lesson_number" : grade.lesson_number, "item_id" : grade.item_id, "group_id" : grade.group_id, "date" : grade.date, "student_id" : grade.student_id})
        connection.commit()
        return {"status" : "success", "message" : "Grade was successfully deleted."}
    
@app.post('/schedule/lesson/change_grade')
async def change_grade(grade : SetGrade, credentials: HTTPAuthorizationCredentials = Depends(bearer)):
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
        if rows[0][2] == "teacher":
            sql = text("SELECT * FROM items WHERE teacher_id = :teacher_id and id = :item_id")
            result = connection.execute(sql, {"teacher_id": rows[0][7], "item_id": grade.item_id})
            rows = result.fetchall()
            if not rows:
                return {"status": "info", "message": "Not your item to deal with grades."}

            sql = text("SELECT * FROM students WHERE id = :student_id AND group_id = :group_id")
            result = connection.execute(sql, {"student_id": grade.student_id, "group_id": grade.group_id})
            student = result.fetchall()
            if not student:
                return {"status": "info", "message": "Student not found in this group."}
        sql = text("""SELECT * FROM grades 
                    WHERE item_id = :item_id AND group_id = :group_id 
                    AND lesson_number = :lesson_number AND date = :date 
                    AND student_id = :student_id""")
        result = connection.execute(sql, {
            "item_id": grade.item_id, "group_id": grade.group_id,
            "lesson_number": grade.lesson_number, "date": grade.date,
            "student_id": grade.student_id
        })
        if not result.fetchall():
            return {"status": "info", "message": "Grade not found."}
        sql = text("UPDATE grades SET grade = :grade WHERE item_id = :item_id and group_id = :group_id and lesson_number = :lesson_number and date = :date and student_id = :student_id")
        result = connection.execute(sql, {"grade" : grade.grade, "lesson_number" : grade.lesson_number, "item_id" : grade.item_id, "group_id" : grade.group_id, "date" : grade.date, "student_id" : grade.student_id})
        connection.commit()
        return {"status" : "success", "message" : "Grade was successfully changed."}
    
@app.get("/adminpanel")
async def admin_panel(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
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
        if rows[0][2] != "admin":
            return {"status" : "info", "message" : "You cant do that."}
        sql = text("SELECT * FROM users")
        result = connection.execute(sql)
        rows = result.fetchall()
        users_list = []
        for user in rows:
            user = list(user)
            user[4] = "***"
            users_list.append(user)
        return {"status": "success", "message": "Successfully fetched all user data.", "users": users_list}

@app.post("/adminpanel/changepassword")
async def change_password(user: ChangePass, credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    token = credentials.credentials
    try:
        decoded = jwt.decode(token, secret, algorithms=["HS256"])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user_id = decoded["id"]
    with engine.connect() as connection:
        sql = text("SELECT * FROM users WHERE id = :id")
        result = connection.execute(sql, {"id": user_id})
        rows = result.fetchall()
        if rows[0][2] != "admin":
            return {"status": "info", "message": "You cant do that."}

        sql = text("SELECT * FROM users WHERE login = :login")
        result = connection.execute(sql, {"login": user.login})
        target = result.fetchall()
        if not target:
            return {"status": "info", "message": "User not found."}

        new_hash = bcrypt.hashpw(user.new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        sql = text("UPDATE users SET password = :password WHERE login = :login")
        connection.execute(sql, {"password": new_hash, "login": user.login})
        connection.commit()
    return {"status": "success", "message": "Password changed successfully."}