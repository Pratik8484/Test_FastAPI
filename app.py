#%% Import Libraries
import time
import traceback
import validation as vldn
import transform_template as tt
from flask import Flask, render_template,redirect, request, make_response, send_file, abort, jsonify
from waitress import serve
from flask_sqlalchemy import SQLAlchemy
import os,sys
from datetime import datetime
from LOGINJECTOR import LOG_INJECTION
import pandas as pd
from io import BytesIO
import uvicorn
import uuid



## new imports login ldap

from fastapi import FastAPI, Form, HTTPException, Depends, Request
from fastapi.security import APIKeyCookie
from fastapi.templating import Jinja2Templates
from fastapi.encoders import jsonable_encoder
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.gzip import GZipMiddleware
from starlette.responses import Response, HTMLResponse, RedirectResponse, StreamingResponse
from starlette import status

from pathlib import Path

from utils import OAuth2PasswordBearerWithCookie
from datetime import datetime, timedelta, date
from forms.forms import LoginForm
from models.model import Token, TokenData
from jose import JWTError, jwt
import logging

from auth.helper import AuthenticateUser
from typing import List
import json
from office365.sharepoint.client_context import ClientContext
from office365.runtime.auth.authentication_context import AuthenticationContext
import shutil

from werkzeug.utils import secure_filename

import openpyxl
from fastapi.middleware.wsgi import WSGIMiddleware
import re
import asyncio


##------------------------

path= os.getcwd()
config_path = os.path.join(path, 'config.json')
config_path2 = os.path.join(path, 'prod_settings.json')

with open(config_path) as f:
    config = json.load(f)

with open(config_path2) as f:
    prod_settings = json.load(f)    

app_settings = {'url': prod_settings['url'],
               'client_id': prod_settings['client_id'],
               'client_secret': prod_settings['client_secret']}


SECRET_KEY = prod_settings['secret_key']
ALGORITHM = config['algorithm']
ACCESS_TOKEN_EXPIRE_MINUTES = config['access_token_expiry']  


app = FastAPI()

flask_app = Flask(__name__)
flask_app.config['SECRET_KEY'] = b'_5#y2L"F4Q8z\n\xec]/'
flask_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
flask_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(flask_app)

toolname = "UNIDENTIFIED ESF"


app.mount("/unidentified", WSGIMiddleware(flask_app))

app.add_middleware(GZipMiddleware, minimum_size=500)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory=os.path.abspath(os.path.expanduser('templates')))#

cookie_sec = APIKeyCookie(name="session")

##new 

oauth_2_scheme = OAuth2PasswordBearerWithCookie(tokenUrl="token")

def list_append(app_settings, list_name, row_dict):
    list_append_status = ""
    try:
        context_auth = AuthenticationContext(url=app_settings['url'])
        context_auth.acquire_token_for_app(client_id=app_settings['client_id'], client_secret=app_settings['client_secret'])
        
        ctx = ClientContext(app_settings['url'], context_auth)
        web = ctx.web
        ctx.load(web)
        ctx.execute_query()
        
        lis = web.lists.get_by_title(list_name)     
        lis.add_item(row_dict)
        ctx.execute_query()
        list_append_status = True
    except Exception as e:
        print(e)
        list_append_status = False
    return list_append_status


def authenticate_user(username: str, password: str):
    
    user = AuthenticateUser(config['ldap_server'], config['ldap_base_dn'], config['ldap_access_group']).verify_user(username, password)
    print('authenticate_user:',user)

    if user['status'] == 'Active' or user['status'] == 'Inactive':
        return user
    else:
        return False
    


def create_access_token(data: dict, expires_delta: timedelta or None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
        
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    return encoded_jwt


# async def get_current_user(token:str = Depends(oauth_2_scheme)):
#     credential_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials!", headers={"WWW-Authenticate": "Bearer"})
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         username: str = payload.get("sub")
#         if username is None:
#             raise credential_exception
#         token_data = TokenData(user_name=username)
#     except JWTError:
#         raise credential_exception
    
#     return username

async def get_current_user(token: str = Depends(oauth_2_scheme)):
    try:
        payload, crypto_segment = token.rsplit(b".", 1)  # Explicitly call rsplit on payload
        username = jwt.decode(payload, SECRET_KEY, algorithms=[ALGORITHM])["sub"]
        return username
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# @app.post("/login", response_model=Token)
# async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
# @app.post("/login", response_model=Token)
@app.post("/login", response_model=Token)
async def login_for_access_token(request: Request):

    form = LoginForm(request)
    await form.load_data()
    #errors = await form.is_valid(db)
    user = authenticate_user(form.username,form.password)
    print('user:',user['user_name'])
    if not user:
        #logger.error('Invalid user - {}'.format(form.username))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail = 'Incorrect username or password', headers={"WWW-Authenticate": "Bearer"})
    
    if user['status'] == 'Inactive':
        #logger.error('Invalid user - {}'.format(form.username))
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail = 'User not a member of application', headers={"WWW-Authenticate": "Bearer"})
        
    # access_token_expires = ACCESS_TOKEN_EXPIRE_MINUTES
    expires_delta = timedelta(minutes = ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data = {"sub": user['user_name']}, expires_delta=expires_delta)

    return {"access_token":access_token, "token_type": "bearer"}


@app.post("/registerUser")
async def add_new_user(request: Request):
    form = LoginForm(request)
    await form.load_data()
    user = AuthenticateUser(config['ldap_server'], config['ldap_base_dn'], config['ldap_access_group']).request_access(form.username, form.password)
    #user = None
    if not user:
        #logger.error("Invalid user -- {}".format(form.username))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail = 'Incorrect username or password', headers={"WWW-Authenticate": "Bearer"})
    else:
        po_email = config['owner_email']
        from_email = config['saccount_email']
        sp_list_row_dict = {
                            "To": user['mail']+';'+po_email,
                            "From": from_email,  
                            'CC': user['managerMail'],
                            "SUBJECT": f"Unidentified tool access request {form.username}",
                            "MESSAGE": f' Please register user {form.username} with the ldap group to allow access to Unidentified tool.'}
        list_name = "UNIDENTIFIED_ACCESS_EMAIL"
        list_append_status = list_append(app_settings, list_name, sp_list_row_dict)
        print(list_append_status)#   
        

@app.get('/login', name='start_page')
async def login(request:Request):
    return templates.TemplateResponse('login.html', context={'request': request})#
    #return render_template('login.html', context={'request': request})

@app.get('/register')
async def register_user(request:Request):
    return templates.TemplateResponse('register.html', context={'request': request}) 


#old
class db_mapping(db.Model):  
    id = db.Column(db.Integer, primary_key=True)
    Fafed_ORG = db.Column(db.String(256))
    INT_ORG = db.Column(db.String(256))
    Status = db.Column(db.String(256))

    def to_dict(self):
        return {
            'id': self.id,
            'Fafed_ORG': self.Fafed_ORG,
            'INT_ORG': self.INT_ORG,
            'Status': self.Status
        }

with flask_app.app_context():
    db.create_all()

@flask_app.route('/')
async def index():
    current_user = await get_current_user()
    print('current user:',current_user)
    if not current_user:
        # Handle the case where the user is not authenticated
        return render_template("error.html", error="User not authenticated")

    # Extract the user ID from the current_user dictionary
    user_id = current_user

    return render_template("index.html", user_id=user_id)

@flask_app.route('/validation', methods=['GET'])
def validation_webpage():


    return render_template('validation.html')

@flask_app.route('/mapping')
def mapping():
    return render_template('mapping.html')

@flask_app.route('/map')
def map():
    return render_template('map.html')

@flask_app.route('/validation', methods=['POST'])
def validation_process():
    exceptionmessage = ""
    process_status = ""
    success_message = ""
    failure_message = ""
    start_time = time.time()
    try:               
        input_file_path = request.files['inputFile']
        activity = request.form.get('activity')
        lanID = request.form['LanID']
        
        validation_cls = vldn.Validation(input_file_path, activity, db_mapping)
        
        validation_cls.changing_datatype()
        validation_cls.replace_special_chars()
        validation_cls.formatting()
        validation_cls.remove_white_space()
        validation_cls.compare_orgs_with_db()
        validation_cls.validate_outlate()
        validation_cls.validate_duplicate_entry()
        validation_cls.execute_sql_queries()
        validation_cls.compare_sirval_tdo()
        
        output_df = validation_cls.generate_output()
    
        response = make_response(output_df.to_csv(index=False, encoding='utf-8-sig').encode('utf-8-sig'))
        output_filename = 'output_'+input_file_path.filename.split()[-1][:-5]
        cd = f'attachment; filename={output_filename}.csv'
        response.headers['Content-Disposition'] = cd
        response.mimetype = 'text/csv' 
        
        process_status = "SUCCESSFUL"
        success_message = f"Lan ID : {lanID},   Activity : {activity},   Input File name : {input_file_path}"

    except:

        process_status = "UNSUCCESSFUL"
        exc_type,exc_value,exc_tb = sys.exc_info()
        errormessage_ls = traceback.format_exception(exc_type,exc_value,exc_tb)
        exceptionmessage = exceptionmessage + " ".join(errormessage_ls)
        exception_String = f"Error : {exceptionmessage}"
        failure_message = f"Lan ID : {lanID},   Activity : {activity},   Input File name : {input_file_path},    {exception_String}"
    end_time = time.time()

    utc_datetime = datetime.utcnow()
    utc_time = utc_datetime.strftime("%H:%M:%S")

    
    functionality = "VALIDATION"
    status = process_status
    
    if process_status =="SUCCESSFUL":
        logtrasnfer,log_exceptionmessage = LOG_INJECTION(toolname,utc_time,functionality,status,start_time,end_time,success_message)
        
    else:
        logtrasnfer,log_exceptionmessage = LOG_INJECTION(toolname,utc_time,functionality,status,start_time,end_time,failure_message)
        


    if process_status == "SUCCESSFUL":
        return response
         
    return render_template('validation.html', error_message=exceptionmessage)



@flask_app.route('/download_sample_headers', methods=['GET'])
def download_sample_headers():   
    sample_header_file_path = 'assets/sample_header_file.xlsx'
    return send_file(sample_header_file_path, as_attachment=True)
    
@flask_app.route('/transform_template', methods=['GET'])
def transform_template_webpage():    
    return render_template('transform_template.html')

@flask_app.route('/transform_template', methods=['POST'])
def transform_template_process():    
    exceptionmessage = ""
    process_status = ""
    success_message = ""
    failure_message = ""
    start_time = time.time()
    try:            
        input_file_path = request.files['inputFile']
        lanID = request.form['LanID']

        transform_template =tt.transform_template(input_file_path)
        
        transform_template.changing_datatype()
      
        transform_template.replace_special_chars()
        
        transform_template.formatting()
     
        transform_template.remove_white_space()
        
        output_df = transform_template.generate_output()
       

        response = make_response(output_df.to_csv(index=False, sep='\t', encoding='utf-8-sig').encode('utf-8-sig'))
        
        cd = 'attachment; filename=transformed_template.txt'
        response.headers['Content-Disposition'] = cd
        response.mimetype = 'text/csv'

        process_status = "SUCCESSFUL"
        success_message = f"Lan ID : {lanID},   Input File name : {input_file_path}"

        
    except:
        process_status = "UNSUCCESSFUL"
        exc_type,exc_value,exc_tb = sys.exc_info()
        errormessage_ls = traceback.format_exception(exc_type,exc_value,exc_tb)
        exceptionmessage = exceptionmessage + " ".join(errormessage_ls)
        exception_String = f"Error : {exceptionmessage}"
        failure_message = f"Lan ID : {lanID},   Input File name : {input_file_path},   {exception_String}"
    end_time = time.time()
    
    utc_datetime = datetime.utcnow()
    utc_time = utc_datetime.strftime("%H:%M:%S")

    functionality = "TRANSFORM TEMPLATE"
    status = process_status
    

    if process_status =="SUCCESSFUL":
        logtrasnfer,log_exceptionmessage = LOG_INJECTION(toolname,utc_time,functionality,status,start_time,end_time,success_message)
        
    else:
        logtrasnfer,log_exceptionmessage = LOG_INJECTION(toolname,utc_time,functionality,status,start_time,end_time,failure_message)
        

    if process_status == "SUCCESSFUL":
        return response

    return render_template('transform_template.html', error_message=exceptionmessage)
        
@flask_app.route('/data', methods=['GET'])
def get_data():
    data = db_mapping.query.all()
    data_list = [{"id": item.id, "Fafed_ORG": item.Fafed_ORG, "INT_ORG": item.INT_ORG, "Status": item.Status} for item in data]
    return jsonify(data_list)

@flask_app.route('/add_data', methods=['POST'])
def add_data():
    fafed_org = request.form['fafed_org']
    int_org = request.form['int_org']
    status = request.form['status']

    new_data = db_mapping(Fafed_ORG=fafed_org, INT_ORG=int_org, Status=status)
    db.session.add(new_data)
    db.session.commit()

    return jsonify({"message": "Data added successfully"})

@flask_app.route('/edit_data/<int:id>', methods=['PUT'])
def edit_data(id):
    data = db_mapping.query.get(id)
    if data:
        data.Fafed_ORG = request.form['fafed_org']
        data.INT_ORG = request.form['int_org']
        data.Status = request.form['status']

        db.session.commit()
        return jsonify({"message": "Data updated successfully"})
    else:
        return jsonify({"error": "Data not found"}), 404

@flask_app.route('/delete_data/<int:id>', methods=['DELETE'])
def delete_data(id):
    data = db_mapping.query.get(id)
    if data:
        db.session.delete(data)
        db.session.commit()
        return jsonify({"message": "Data deleted successfully"})
    else:
        return jsonify({"error": "Data not found"}), 404


@flask_app.route('/export-data', methods=['GET'])
def export_data():
    data = db_mapping.query.all()
    data_list = [{"id": item.id, "Fafed_ORG": item.Fafed_ORG, "INT_ORG": item.INT_ORG, "Status": item.Status} for item in data]
    
    df = pd.DataFrame(data_list)

    excel_data = BytesIO()
    with pd.ExcelWriter(excel_data, engine='xlsxwriter', mode='w') as writer:
        df.to_excel(writer, sheet_name='mapping', index=False)

    excel_data.seek(0)

    response = make_response(excel_data.read())
    response.headers["Content-Disposition"] = "attachment; filename=mapping_export.xlsx"
    response.headers["Content-Type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

    return response


@app.get("/logout")
def logout(request: Request, response: Response, username: str =  Depends(get_current_user)):

    current_user = username
    print('sessiondata:',current_user)
    response.delete_cookie("access_token")

    if not current_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='User not authenticated')

    response.delete_cookie("session")

    content = templates.TemplateResponse(
        "logout.html",
        {"request": request, "username": current_user}
    )
    
    return content

    # content = """
    # <html>
    # <head>
    #     <style>
    #         body {
    #             font-family: 'Arial', sans-serif;
    #             background-color: #f0f0f0;
    #             text-align: center;
    #             margin-top: 100px;
    #         }

    #         .logout-message {
    #             font-size: 18px;
    #             color: #333;
    #         }

    #         .countdown {
    #             font-size: 24px;
    #             color: #ff6347;
    #             font-weight: bold;
    #         }
    #     </style>
    # </head>
    # <body>
    #     <div class="logout-message">
    #         <p>You are logged out.</p>
    #         <p>Redirecting to login page in <span class="countdown" id="countdown">5</span> seconds...</p>
    #     </div>
        
    #     <script>
    #         var countdown = 5;
    #         function updateCountdown() {
    #             document.getElementById('countdown').innerText = countdown;
    #             if (countdown > 0) {
    #                 countdown--;
    #                 setTimeout(updateCountdown, 1000);
    #             } else {
    #                 window.location.href = '/login';
    #             }
    #         }
    #         updateCountdown();
    #     </script>
    # </body>
    # </html>
    # """
    
    # return HTMLResponse(content=content)




# if __name__ == '__main__':  
#     #serve(flask_app,host='0.0.0.0',port = 9874,threads=6)
#     uvicorn.run(app, port=9874, host='0.0.0.0')    


