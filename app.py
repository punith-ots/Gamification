import configparser
import os
from datetime import datetime

import hashlib
import jwt
import mysql.connector
from flask import Flask, request, jsonify
from flask_cors import CORS


from Badgerule import *
from TasksExtraction import *
from ruleexecution import calculation
from criteria import criteriaCalculation


app = Flask(__name__)   
AddLink = 'https://open.ortusolis.com/openproject/projects' + '/'
app.secret_key = os.urandom(24)
config = configparser.ConfigParser()
config.read('config.ini')
app.config.from_pyfile(os.path.join(".", "app.conf"), silent=False)
Key = app.config.get("KEY")
TheParams = app.config.get("PARAM")
Link = app.config.get("LINK")
cors = CORS(app, resources={r"/*": {"origins": "*"}})
CORS(app, supports_credentials=True)
app.config['CORS_HEADERS'] = 'Content-Type'


@app.route("/signup", methods=["POST"])
def user_signup():
    User_Data = request.get_json()      # gets the Request data from API

    # Looking for KeyError in request
    for key in {'userName', 'email', 'password'}:
        try:
            User_Data[key]
        except KeyError:
            return {"Response_status": "Fail", "Response_description": "KeyError", "Response_code": 500}

    # Assigning user data values to variables
    userName = User_Data['userName']
    email = User_Data['email']
    password = User_Data['password']
    # phone = User_Data['phone']

    try:
        # Database connection
        Conn = mysql.connector.connect(host='191.101.230.52', user='u565063885_emp_dash', password='Gamify@ots#db@24', database='u565063885_Gamification')
        cursor = Conn.cursor()

        # Execute the SQL query
        # Query to check user is valid and exist in openproject as Active user
        cursor.execute("SELECT * FROM user_details WHERE email = %s and status = 'Active'", (email,))
        user_valid = cursor.fetchall()   # Fetching the data

        # If the user is exist in openproject (Valid User)
        if len(user_valid) != 0:
            Admin = user_valid[0][5]
            # print(Admin)
            if Admin != '1':
                # print("USER")
                # Query to check user is already Registered
                cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
                user_exist = cursor.fetchall()
                # If user is not Registered --> REGISTER
                if len(user_exist) == 0:
                    try:
                        protected_password = hashlib.md5(password.encode('utf-8')).hexdigest()
                        cursor.execute("INSERT INTO users (user_name, email, password ) VALUES(%s, %s, %s)",(userName, email, protected_password))
                        Conn.commit()
                    except mysql.connector.IntegrityError:
                        return {"Response_status": "Fail", "Response_description": "Duplicate entry", "Response_code": 500}
                    return {"Response_status": "Success", "Response_description": "User Added Successfully", "Response_code": 200}

                # If user is already Registered --> Don't REGISTER
                else:
                    return {"Response_status": "Fail", "Response_description": "User Already Exists", "Response_code": 404}
            elif Admin == '1':
                # print("ADMIN")
                # Query to check user is already Registered
                cursor.execute("SELECT * FROM admin_users WHERE email = %s", (email,))
                admin_exist = cursor.fetchall()
                # If user is not Registered --> REGISTER
                if len(admin_exist) == 0:
                    try:
                        protected_password = hashlib.md5(password.encode('utf-8')).hexdigest()
                        cursor.execute("INSERT INTO admin_users (user_name, email, password ) VALUES(%s, %s, %s)",
                                       (userName, email, protected_password))
                        Conn.commit()
                    except mysql.connector.IntegrityError:
                        return {"Response_status": "Fail", "Response_description": "Duplicate entry",
                                "Response_code": 500}
                    return {"Response_status": "Success", "Response_description": "Admin Added Successfully",
                            "Response_code": 200}

                # If user is already Registered --> Don't REGISTER
                else:
                    return {"Response_status": "Fail", "Response_description": "User Already Exists",
                            "Response_code": 404}

        # If the user is NOT EXIST in openproject (Invalid User) --> Don't allow to Register
        else:
            return {"Response_status": "Fail", "Response_description": "Invalid Mail-Id ", "Response_code": 404}
    except Exception as e:
        return {"Response_status": "Fail", "Response_description": e, "Response_code": 500}




@app.route("/login", methods=["POST"])
def user_login():
    Admin_Data = request.get_json()  # gets the Request data from API

    # Looking for KeyError in request
    for key in {'email', 'password'}:
        try:
            Admin_Data[key]
        except KeyError:
            return {"Response_status": "Fail", "Response_description": "KeyError", "Response_code": 500}
    email = Admin_Data['email']
    # if email == "shachi.yelandur@ortusolis.com":
    #     email = "admin"
    password = Admin_Data['password']
    admin_password = hashlib.md5(password.encode('utf-8')).hexdigest()
    try:
        Conn = mysql.connector.connect(host='191.101.230.52', user='u565063885_emp_dash', password='Gamify@ots#db@24',
                                       database='u565063885_Gamification')
        cursor = Conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        rowheader = [x[0] for x in cursor.description]
        result = cursor.fetchall()
        Admin_Jsondata = []
        if len(result) == 0:
            return {"Response_status": "Fail", "Response_description": "Admin Not Exists", "Response_code": 404}
        else:
            for i in result:
                Admin_Jsondata.append(dict(zip(rowheader, i)))
            password1 = Admin_Jsondata[0]['password']
            if admin_password != password1:
                return {"Response_status": "Fail", "Response_description": "Incorrect password", "Response_code": 500}
            cursor.close()
            EncodedJwt = jwt.encode({"mail": email}, "secret", algorithm="HS256")
            del Admin_Jsondata[0]['password']
            Admin_Jsondata[0]['jwt'] = EncodedJwt
            return {"Response_status": "Success", "Response_description": "Login Successful", "Response_code": 200,
                    "Admin_details": Admin_Jsondata}
    except Exception as e:
        return {"Response_status": "Fail", "Response_description": e, "Response_code": 500}




######################
# Generate Jwt token #
######################
@app.route("/JwtGenerator", methods=["POST"])
def JwtGenerator():
    api_url = "https://open.ortusolis.com/openproject/api/v3/users/me"
    r = requests.get(api_url, auth=Key, params=TheParams)
    j = r.json()
    print(j)
    try:
        Data = request.get_json()
        # print("1")
        Mail = Data['mail']
        # Response = {}
        if Mail == "shachi.yelandur@ortusolis.com":
            Mail = "admin"
            Flag = 1
            # print("2")
        else:
            Flag = 2
            # print("2")
        # Database connection
        Db = yaml.load(open('db.yaml'), Loader=FullLoader)
        Cnx = mysql.connector.connect(host=Db['mysql_host'], user=Db['mysql_user'],
                                      password=Db['mysql_password'], database=Db['mysql_db'],
                                      auth_plugin=Db['mysql_auth'])
        # Cnx = mysql.connector.connect(host='191.101.230.52', user='u565063885_emp_dash', password='Gamify@ots#db@24',
        #                               database='u565063885_Gamification', auth_plugin='mysql_native_password')
        cursor = Cnx.cursor()
        # print("3")
        cursor.execute("""SELECT email FROM user_details WHERE Status='Active' and email = '%s' """ % Mail)
        User = [x[0] for x in cursor.fetchall()]  # Fetch the details
        cursor.close()
        if User:
            # print("4")
            EncodedJwt = jwt.encode({"mail": Mail}, "secret", algorithm="HS256")
            Response = {"responseCode": 200, "responseDescription": "User found", "responsestate": "Success",
                        "role": Flag, "JwtToken": EncodedJwt}
        elif Mail == "":
            # print("5")
            Response = {"responseCode": 200, "responseDescription": "Please Enter Email-Id", "responsestate": "Fail"}
        else:
            # print("6")
            Response = {"responseCode": 200, "responseDescription": "User not found", "responsestate": "Fail"}
        return Response
    except Exception as E:
        # print("7")
        if not Data:
            Response = {"responseCode": 400, "responseDescription": "Bad Request", "responsestate": "Fail"}
            return Response
        else:
            return {"respondecode": 500, "responseDescription": E}


#################################################################
# To get all the tasks that are open in all the active projects #
#################################################################
@app.route("/myprojects", methods=["POST"])
def RelatedProjectsAllTasks():
    try:
        Data = request.get_json()
        if Data['jwt'] == "":
            Response = {"responseCode": 400, "responseDescription": "Invalid Token", "responsestate": "Fail"}
            return Response
        EncodedJwt = Data['jwt']
        DecodedJwt = jwt.decode(EncodedJwt, "secret", algorithms=["HS256"])
        Mail = DecodedJwt['mail']
        Url = 'https://open.ortusolis.com/openproject/api/v3/users?filters=[{"login":{"operator":"=","values":["' + Mail + '"]}}]'
        Request = requests.get(Url, auth=Key, params=TheParams)
        Response = Request.json()
        Data = Response['_embedded']['elements']
        # for parsing the openproject response from TasksExtraction file
        return MyProjects(Data, Key, Link, TheParams)
    except Exception as E:
        if not Data:
            Response = {"responseCode": 400, "responseDescription": "Bad Request", "responsestate": "Fail"}
            return Response
        else:
            return {"respondecode": 500, "responseDescription": E}


#######################################################################################
# To get all the tasks that are open in all the active projects within the given time #
#######################################################################################
@app.route("/myprojects/datefilter", methods=["POST"])
def RelatedProjectsAllTasksFilter():
    try:
        related_project = []
        FilteredResponse = {}
        FinalResponse = []
        projects = []
        Data = request.get_json()
        EncodedJwt = Data['jwt']
        DecodedJwt = jwt.decode(EncodedJwt, "secret", algorithms=["HS256"])
        Mail = DecodedJwt['mail']
        start_date1 = Data['startDate']
        start_date = start_date1[6:] + "-" + start_date1[:2] + "-" + start_date1[3:5]
        if Data['endDate'] is not None:
            end_date1 = Data['endDate']
        else:
            end_date1 = start_date
        end_date = end_date1[6:] + "-" + end_date1[:2] + "-" + end_date1[3:5]
        url = 'https://open.ortusolis.com/openproject/api/v3/users?filters=[{"login":{"operator":"=","values":["' + Mail + '"]}}]'
        r = requests.get(url, auth=Key, params=TheParams)
        j = r.json()
        Data = j['_embedded']['elements']
        print("1")
        for Item in Data:
            ProjectsListLink = Link + str(Item['_links']['memberships']['href'])
            ProjectsMembership = requests.get(ProjectsListLink, auth=Key)
            ProjectsApiResponse = ProjectsMembership.json()
            ProjectsData = ProjectsApiResponse['_embedded']['elements']
            for GetProjects in ProjectsData:
                ProjectLink = Link + str(GetProjects['_links']['project']['href'])
                if ProjectLink != 'https://open.ortusolis.comNone':
                    ProjectLink = ProjectLink + '/work_packages/'
                    related_project.append(ProjectLink)
            # print("RelatedProjects :", RelatedProjects)
            for Row in related_project:
                Link1 = Row.replace("/api/v3", "")
                Row1 = Row + '?filters=[{"startDate":{"operator":"<>d","values":["' + start_date + '","' + end_date + '"]}}]'
                Request = requests.get(Row1, auth=Key, params=TheParams)
                j = Request.json()
                try:
                    data = j['_embedded']['elements']
                except KeyError:
                    pass
                try:
                    for Value in data:
                        TaskType = Value['_links']['type']['title']
                        if TaskType == "Task" or TaskType == "Bug":
                            Priority = Value['_links']['priority']['title']
                            if TaskType == "Bug":
                                Complexity = Value['_links']['customField9']['title']
                            ProjectName = Value['_links']['project']['title']
                            if ProjectName not in projects:
                                projects.append(ProjectName)
                            Parent_id = str(Value['_links']['parent']['href'])
                            ParentId = Parent_id[34:38]
                            if ParentId == "":
                                ParentLink1 = ""
                            else:
                                ParentLink1 = Link1 + str(Parent_id) + "/activity"
                            ParentLink = ParentLink1
                            TaskId = Value['id']
                            TaskLink = Link1 + str(Value['id']) + "/activity"
                            TaskSubject = Value['subject']
                            TaskAuthor = Value['_links']['author']['title']
                            try:
                                TaskAssignee = Value['_links']['assignee']['title']
                            except KeyError:
                                TaskAssignee = TaskAuthor
                            if TaskType == "Task":
                                Complexity = Value['_links']['customField3']['title']

                                Cnx = mysql.connector.connect(host='191.101.230.52', user='u565063885_emp_dash',
                                                              password='Gamify@ots#db@24',
                                                              database='u565063885_Gamification',
                                                              auth_plugin='mysql_native_password')
                                cursor = Cnx.cursor()

                                # query for priority points
                                cursor.execute(
                                    """SELECT points FROM Priority WHERE title = '%s'""" % Priority)
                                PriorityTuple = cursor.fetchone()
                                PriorityPoints = PriorityTuple[0]
                                # print(PriorityPoints)

                                # query for DefectSeverity points
                                cursor.execute(
                                    "SELECT points FROM Complexity WHERE title = '%s'" % Complexity)
                                ComplexityTuple = cursor.fetchone()
                                # if ComplexityTuple is not None:
                                ComplexityPoints = ComplexityTuple[0]

                                # Point Calculation for TASK
                                Allotted_Points = (PriorityPoints + ComplexityPoints)
                                cursor.close()
                            else:
                                Allotted_Points = 0

                            TaskPercentage1 = Value['percentageDone']
                            TaskPercentage = str(TaskPercentage1) + "%"

                            TaskStatus = Value['_links']['status']['title']

                            Task_estimated_Time = str(Value['estimatedTime']).replace('P', '').replace('D', '*24'). \
                                replace('T', '+').replace('H', '+').replace('M', ' /2').replace('S', '')
                            if Task_estimated_Time is not None:
                                if Task_estimated_Time.endswith('+'):
                                    Task_estimated_Time = Task_estimated_Time[:-1]
                                elif Task_estimated_Time.startswith('+'):
                                    Task_estimated_Time = Task_estimated_Time[1:]
                            TaskEstimatedTime = eval(Task_estimated_Time)

                            Task_spent_Time = str(Value['spentTime']).replace('P', '').replace('D', '*24').replace('T',
                                                                                                                   '+').replace(
                                'H', '+').replace('M', ' /2').replace('S', '')
                            if Task_spent_Time is not None:
                                if Task_spent_Time.endswith('+'):
                                    Task_spent_Time = Task_spent_Time[:-1]
                                elif Task_spent_Time.startswith('+'):
                                    Task_spent_Time = Task_spent_Time[1:]
                            TaskSpentTime = eval(Task_spent_Time)

                            TaskCreatedAt_1 = Value['createdAt']
                            Task_Created_at1 = pd.to_datetime(TaskCreatedAt_1)
                            TaskCreatedDate = Task_Created_at1.date()

                            try:
                                TaskStartDate = Value['startDate']
                            except KeyError:
                                TaskStartDate = TaskCreatedDate
                            except AttributeError:
                                TaskStartDate = TaskCreatedDate

                            TaskUpdatedAt_1 = Value['updatedAt']
                            Task_Updated_at1 = pd.to_datetime(TaskUpdatedAt_1)
                            TaskUpdatedDate1 = Task_Updated_at1.date()
                            TaskUpdatedDate = TaskUpdatedDate1.strftime('%Y-%m-%d')
                            # print("TaskUpdatedAt_1 :", TaskUpdatedAt_1)
                            # print("Task_Updated_at1 :", Task_Updated_at1)
                            # print("TaskUpdatedDate1 :", TaskUpdatedDate1)
                            # print("TaskUpdatedDate :", TaskUpdatedDate)

                            try:
                                TaskDueDate = Value['dueDate']
                                if TaskDueDate is None:
                                    TaskDueDate = TaskStartDate
                            except KeyError:
                                TaskDueDate = TaskStartDate
                            TaskDueDate2 = pd.to_datetime(TaskDueDate)
                            r = TaskDueDate2.date()
                            if r < TaskUpdatedDate1:
                                StatusCode = 'red'
                            elif r == TaskUpdatedDate:
                                StatusCode = 'yellow'
                            else:
                                StatusCode = "green"
                            # Task_Status = get_id['_links']['status']['title']
                            if TaskStatus == "On hold":
                                StatusCode = 'grey'

                            FilteredResponse.update(
                                {'ProjectName': ProjectName, 'ParentId': ParentId, 'ParentLink': ParentLink,
                                 "TaskId": TaskId, 'TaskLink': TaskLink, 'TaskSubject': TaskSubject,
                                 'TaskAssignee': TaskAssignee, 'TaskType': TaskType, 'Allotted_Points': Allotted_Points,
                                 'Priority': Priority, 'Complexity': Complexity, 'TaskPercentage': TaskPercentage,
                                 'TaskEstimatedTime': TaskEstimatedTime, 'TaskSpentTime': TaskSpentTime,
                                 'TaskStartDate': TaskStartDate, 'TaskUpdatedDate': TaskUpdatedDate,
                                 'TaskDueDate': TaskDueDate, 'TaskStatus': TaskStatus, 'StatusCode': StatusCode
                                 })
                            FinalResponse.append(FilteredResponse.copy())
                except Exception as e:
                    pass
        return {"project_list": projects, "key": FinalResponse}
    except Exception as e:
        return {"respondecode": 500, "responseDescription": e}


########################
# To get all the tasks #
########################
@app.route("/mytasks", methods=["POST"])
def RelatedProjectsAssigneeTasks():
    try:
        Data = request.get_json()
        if Data['jwt'] == "":
            Response = {"responseCode": 400, "responseDescription": "Invalid Token", "responsestate": "Fail"}
            return Response
        else:
            EncodedJwt = Data['jwt']
            DecodedJwt = jwt.decode(EncodedJwt, "secret", algorithms=["HS256"])
            Mail = DecodedJwt['mail']
            FilteredResponse = {}
            RelatedProjects = []
            FinalResponse = []
            try:
                url = 'https://open.ortusolis.com/openproject/api/v3/users?filters=[{"login":{"operator":"=","values":["' + Mail + '"]}}]'
                r = requests.get(url, auth=Key, params=TheParams)
                j = r.json()
                Data = j['_embedded']['elements']
                for get_i in Data:
                    Id = str(get_i['id'])
                    # url2 = 'https://open.ortusolis.com/openproject/api/v3/work_packages?filters=[{ "status": { "operator": "!","values":["13"]}}] '
                    url2 = 'https://open.ortusolis.com/openproject/api/v3/work_packages?filters=[{"assignee":{' \
                           '"operator":"=","values":["' + Id + '"]}},{ "status": { "operator": "!","values":["13"]}}] '
                    work_packages = requests.get(url2, auth=Key, params=TheParams)
                    l = work_packages.json()
                    dat = l['_embedded']['elements']
                    for get_id in dat:
                        Task_Status = get_id['_links']['status']['title']
                        if Task_Status != "Rejected":
                            TaskType = get_id['_links']['type']['title']
                            if TaskType == "Task":
                                Priority = get_id['_links']['priority']['title']
                                Complexity = get_id['_links']['customField3']['title']

                                Cnx = mysql.connector.connect(host='191.101.230.52', user='u565063885_emp_dash',
                                                              password='Gamify@ots#db@24',
                                                              database='u565063885_Gamification',
                                                              auth_plugin='mysql_native_password')
                                cursor = Cnx.cursor()

                                # query for priority points
                                cursor.execute(
                                    """SELECT points FROM Priority WHERE title = '%s'""" % Priority)
                                PriorityTuple = cursor.fetchone()
                                PriorityPoints = PriorityTuple[0]
                                # print(PriorityPoints)

                                # query for DefectSeverity points
                                cursor.execute(
                                    "SELECT points FROM Complexity WHERE title = '%s'" % Complexity)
                                ComplexityTuple = cursor.fetchone()
                                # if ComplexityTuple is not None:
                                ComplexityPoints = ComplexityTuple[0]

                                # Point Calculation for TASK
                                Allotted_Points = (PriorityPoints + ComplexityPoints)
                                cursor.close()
                            else:
                                Allotted_Points = 0
                            Task_id = get_id['id']
                            Task_Subject = get_id['subject']
                            Task_Created_at2 = get_id['createdAt']
                            Task_Created_at1 = pd.to_datetime(Task_Created_at2)
                            Task_Updated_at2 = get_id['updatedAt']
                            Task_Updated_at1 = pd.to_datetime(Task_Updated_at2)
                            Task_Updated_at = Task_Updated_at1.date()
                            Project_name = get_id['_links']['project']['title']
                            Lik = AddLink + str(get_id['_links']['project']['href'])
                            if Lik != 'https://open.ortusolis.comNone':
                                Lik = Lik + '/work_packages/'
                                RelatedProjects.append(Lik)
                            for Row in RelatedProjects:
                                Link1 = Row.replace("/openproject/api/v3/projects/", "")
                            Task_link = Link1 + str(get_id['id']) + "/activity"
                            try:
                                Task_Start_Dat = get_id['startDate']
                                if Task_Start_Dat is None:
                                    Task_Start_Date = Task_Created_at1
                                else:
                                    Task_Start_Date = str(Task_Start_Dat).replace("-", "/")
                            except KeyError:
                                Task_Start_Date = Task_Created_at1
                            try:
                                Task_Due_Dat = get_id['dueDate']
                                if Task_Due_Dat is None:
                                    Task_Due_Date1 = Task_Start_Date
                                else:
                                    Task_Due_Date1 = str(Task_Due_Dat).replace("-", "/")
                            except KeyError:
                                Task_Due_Date1 = Task_Start_Date
                            Task_Due_Date2 = pd.to_datetime(Task_Due_Date1)
                            # print("Task_Due_Date1: ",Task_Due_Date1)
                            # print("Task_Due_Date2: ", Task_Due_Date2)
                            r = Task_Due_Date2.date()
                            # print("r: ", r)
                            if r < Task_Updated_at:
                                Status_code = 'red'
                            elif r == Task_Updated_at:
                                Status_code = 'yellow'
                            else:
                                Status_code = "green"
                            # Task_Status = get_id['_links']['status']['title']
                            if Task_Status == "On hold":
                                Status_code = 'grey'
                            if Task_Status != "Closed":
                                FilteredResponse.update(
                                    {'Task_id': Task_id,
                                     'Task_Subject': Task_Subject,
                                     'Project': Project_name,
                                     'Status_code': Status_code,
                                     'Task_link': Task_link,
                                     'Task_status': Task_Status,
                                     'Allotted_Points': Allotted_Points})
                                FinalResponse.append(FilteredResponse.copy())
            except AttributeError:
                FilteredResponse.update(
                    {"Task_id": None, 'Task_Subject': None, 'Status_code': None, 'Task_link': None,
                     'Task_status': None})
                FinalResponse.append(FilteredResponse.copy())
            return {"key": FinalResponse}
    except Exception as E:
        if not Data:
            Response = {"responseCode": 400, "responseDescription": "Bad Request", "responsestate": "Fail"}
            return Response
        else:
            return {"respondecode": 500, "responseDescription": E}


#########################
# To get all the points #
#########################
@app.route("/points", methods=["POST"])
def points():
    try:
        Data = request.get_json()
        if Data['jwt'] == "":
            Response = {"responseCode": 400, "responseDescription": "Invalid Token", "responsestate": "Fail"}
            return Response
        EncodedJwt = Data['jwt']
        DecodedJwt = jwt.decode(EncodedJwt, "secret", algorithms=["HS256"])
        Mail = DecodedJwt['mail']
        Db = yaml.load(open('db.yaml'), Loader=FullLoader)
        Cnx = mysql.connector.connect(host=Db['mysql_host'], user=Db['mysql_user'],
                                      password=Db['mysql_password'], database=Db['mysql_db'],
                                      auth_plugin=Db['mysql_auth'])
        cursor = Cnx.cursor()
        cursor.execute("""SELECT user_id FROM user_details WHERE Status='Active' and email = '%s'""" % Mail)
        assigneee = [x[0] for x in cursor.fetchall()]
        for i in assigneee:
            cursor.execute("""SELECT SUM(availed_points) FROM points WHERE user_id = '%s'""" % i)
            rv = [x[0] for x in cursor.fetchall()]
            points = ' '.join([str(elem) for elem in rv])
            cursor.execute("SELECT SUM(availed_points) FROM points WHERE YEAR(closed_date) = YEAR(DATE_SUB(CURDATE(), INTERVAL 0 WEEK)) AND WEEK(closed_date) = WEEK(DATE_SUB(CURDATE(), INTERVAL 0 WEEK)) AND user_id = '%s'"% (
                    i))
            # # cursor.execute(
            # #     """SELECT SUM(availed_points) FROM points WHERE YEAR(closed_date) = YEAR(DATE_SUB(CURDATE(), INTERVAL 1 MONTH)) AND MONTH(closed_date) = MONTH(DATE_SUB(CURDATE(), INTERVAL 1 MONTH)) AND user_id = '%s'""" % (
            #         i))
            r = [x[0] for x in cursor.fetchall()]
            weekpoints = ' '.join([str(elem) for elem in r])
            cursor.execute(
                """SELECT SUM(availed_points) AS Project_points, project FROM points WHERE user_id = '%s' GROUP BY Project""" % i)
            row_headers = [x[0] for x in cursor.description]  # this will extract row headers
            rv = cursor.fetchall()
            cursor.close()
            var_fixed = []
            for row in rv:
                var_fixed.append(list(map(str, list(row))))
            json_Data = []
            for result in var_fixed:
                json_Data.append(dict(zip(row_headers, result)))
        # return json.dumps({"total": points, "week": point, "pop_up_points": json_Data})
        return {"total": points, "week": weekpoints, "pop_up_points": json_Data}
    except Exception as E:
        if not Data:
            Response = {"responseCode": 400, "responseDescription": "Bad Request", "responsestate": "Fail"}
            return Response
        else:
            return {"respondecode": 500, "responseDescription": E}


########################
# To know the progress #
########################
@app.route("/Progress", methods=["POST"])
def ProgressTracker():
    try:
        Data = request.get_json()
        if Data['jwt'] == "":
            Response = {"responseCode": 400, "responseDescription": "Invalid Token", "responsestate": "Fail"}
            return Response
        EncodedJwt = Data['jwt']
        DecodedJwt = jwt.decode(EncodedJwt, "secret", algorithms=["HS256"])
        Mail = DecodedJwt['mail']
        ProjectJson = []
        progress = []
        FinalResponse = []
        url = 'https://open.ortusolis.com/openproject/api/v3/users?filters=[{"login":{"operator":"=","values":["' + Mail + '"]}}]'
        r = requests.get(url, auth=Key, params=TheParams)
        j = r.json()
        Data = j['_embedded']['elements']
        for Value in Data:
            Tasks = Link + str(Value['_links']['memberships']['href'])
            projects_memebrship = requests.get(Tasks, auth=Key)
            k = projects_memebrship.json()
            Data1 = k['_embedded']['elements']
            for get_pro in Data1:
                lis = Link + str(get_pro['_links']['project'][
                                     'href']) + "/work_packages" + '?filters=[{ "status": { "operator": "!","values":["13"]}},{"updatedAt": {"operator": ">t-" ,"type": "date_past", "values":["30"]}}]'
                # print("Open:", lis)
                try:
                    project = get_pro['_links']['project']['title']

                    li = Link + str(get_pro['_links']['project'][
                                        'href']) + "/work_packages" + '?filters=[{ "status": { "operator": "=","values":["13"]}},{"updatedAt": {"operator": ">t-" ,"type": "date_past", "values":["30"]}}]'
                    # print("Closed:", li)

                    project_Data = {
                        "project": project,
                        "openlink": lis,
                        "closedlink": li
                    }
                    ProjectJson.append(project_Data)
                except KeyError:
                    pass
            for row in ProjectJson:
                open = requests.get(row["openlink"], auth=Key, params=TheParams)
                Open_Data = open.json()
                try:
                    Total_open = Open_Data['total']
                    closed = requests.get(row["closedlink"], auth=Key, params=TheParams)
                    closed_Data = closed.json()
                    Total_closed = closed_Data['total']
                    total_tasks = Total_closed + Total_open
                    progress.append(
                        {"project": row["project"], "closed": Total_closed, "open": Total_open,
                         "total_tasks": total_tasks})
                except KeyError:
                    pass
            FinalResponse.append(progress.copy())
        return {"progress": progress}
    except Exception as E:
        if not Data:
            Response = {"responseCode": 400, "responseDescription": "Bad Request", "responsestate": "Fail"}
            return Response
        else:
            return {"respondecode": 500, "responseDescription": E}


###########################
# To know the Performance #
###########################
@app.route("/Performance", methods=["POST"])
def PerformanceTotal():
    try:
        Project_JSON_LIST = []
        Planned_TASKS_Last_Month = 0
        Actual_TASKS_Last_Month = 0
        Planned_TASKS_Last_Week = 0
        Actual_TASKS_Last_Week = 0
        Planned_TASKS_Last_Day = 0
        Actual_TASKS_Last_Day = 0
        Performance = []
        FinalResponse = []

        Data = request.get_json()
        if Data['jwt'] == "":
            Response = {"responseCode": 400, "responseDescription": "Invalid Token", "responsestate": "Fail"}
            return Response
        EncodedJwt = Data['jwt']
        DecodedJwt = jwt.decode(EncodedJwt, "secret", algorithms=["HS256"])
        Mail = DecodedJwt['mail']
        url = 'https://open.ortusolis.com/openproject/api/v3/users?filters=[{"login":{"operator":"=","values":["' + Mail + '"]}}]'
        r = requests.get(url, auth=Key, params=TheParams)
        j = r.json()
        Data = j['_embedded']['elements']
        for Value in Data:
            Membership_URL = Link + str(Value['_links']['memberships']['href'])
            Membership_URL_Request = requests.get(Membership_URL, auth=Key)
            Membership_JSON = Membership_URL_Request.json()
            Project_JSON = Membership_JSON['_embedded']['elements']
            for get_project in Project_JSON:
                try:
                    project_list = get_project['_links']['project']['title']

                    Planned_Last_Month_URL = Link + str(get_project['_links']['project'][
                                                            'href']) + "/work_packages" + '?filters=[{"dueDate": {"operator": ">t-" ,"type": "date_past", "values":["30"]}}]'
                    Actual_Last_Month_URL = Link + str(get_project['_links']['project'][
                                                           'href']) + "/work_packages" + '?filters=[{ "status": { "operator": "=","values":["13"]}},{"updatedAt": {"operator": ">t-" ,"type": "date_past", "values":["30"]}}]'

                    Planned_Last_Week_URL = Link + str(get_project['_links']['project'][
                                                           'href']) + "/work_packages" + '?filters=[{"dueDate": {"operator": ">t-" ,"type": "date_past", "values":["7"]}}]'
                    Actual_Last_Week_URL = Link + str(get_project['_links']['project'][
                                                          'href']) + "/work_packages" + '?filters=[{ "status": { "operator": "=","values":["13"]}},{"updatedAt": {"operator": ">t-" ,"type": "date_past", "values":["7"]}}]'

                    Planned_Last_Day_URL = Link + str(get_project['_links']['project'][
                                                          'href']) + "/work_packages" + '?filters=[{"dueDate": {"operator": ">t-" ,"type": "date_past", "values":["1"]}}]'
                    Actual_Last_Day_URL = Link + str(get_project['_links']['project'][
                                                         'href']) + "/work_packages" + '?filters=[{ "status": { "operator": "=","values":["13"]}},{"updatedAt": {"operator": ">t-" ,"type": "date_past", "values":["1"]}}]'
                    project_Data = {
                        "project_list": project_list,
                        "Planned_Last_Month_URL": Planned_Last_Month_URL,
                        "Actual_Last_Month_URL": Actual_Last_Month_URL,
                        "Planned_Last_Week_URL": Planned_Last_Week_URL,
                        "Actual_Last_Week_URL": Actual_Last_Week_URL,
                        "Planned_Last_Day_URL": Planned_Last_Day_URL,
                        "Actual_Last_Day_URL": Actual_Last_Day_URL
                    }
                    Project_JSON_LIST.append(project_Data)
                except KeyError:
                    pass
            for row in Project_JSON_LIST:
                try:
                    # -----------------------   Last MONTH data   -----------------------
                    Planned_Last_Month_JSON = requests.get(row["Planned_Last_Month_URL"], auth=Key, params=TheParams)
                    Planned_Last_Month_DATA = Planned_Last_Month_JSON.json()
                    Planned_TASKS_Last_Month = Planned_TASKS_Last_Month + Planned_Last_Month_DATA['count']

                    Actual_Last_Month_JSON = requests.get(row["Actual_Last_Month_URL"], auth=Key, params=TheParams)
                    Actual_Last_Month_DATA = Actual_Last_Month_JSON.json()
                    Actual_TASKS_Last_Month = Actual_TASKS_Last_Month + Actual_Last_Month_DATA['count']

                    # -----------------------   LAST WEEK data   -----------------------
                    Planned_Last_Week_JSON = requests.get(row["Planned_Last_Week_URL"], auth=Key, params=TheParams)
                    Planned_Last_Week_DATA = Planned_Last_Week_JSON.json()
                    Planned_TASKS_Last_Week = Planned_TASKS_Last_Week + Planned_Last_Week_DATA['count']

                    Actual_Last_Week_JSON = requests.get(row["Actual_Last_Week_URL"], auth=Key, params=TheParams)
                    Actual_Last_Week_DATA = Actual_Last_Week_JSON.json()
                    Actual_TASKS_Last_Week = Actual_TASKS_Last_Week + Actual_Last_Week_DATA['count']

                    # -----------------------   LAST DAY data   -----------------------
                    Planned_Last_Day_JSON = requests.get(row["Planned_Last_Day_URL"], auth=Key, params=TheParams)
                    Planned_Last_Day_DATA = Planned_Last_Day_JSON.json()
                    Planned_TASKS_Last_Day = Planned_TASKS_Last_Day + Planned_Last_Day_DATA['count']

                    Actual_Last_Day_JSON = requests.get(row["Actual_Last_Day_URL"], auth=Key, params=TheParams)
                    Actual_Last_Day_DATA = Actual_Last_Day_JSON.json()
                    Actual_TASKS_Last_Day = Actual_TASKS_Last_Day + Actual_Last_Day_DATA['count']
                except Exception as E:
                    pass
            Performance.append(dict(Planned_TASKS_Last_Month=Planned_TASKS_Last_Month,
                                    Actual_TASKS_Last_Month=Actual_TASKS_Last_Month,
                                    Planned_TASKS_Last_Week=Planned_TASKS_Last_Week,
                                    Actual_TASKS_Last_Week=Actual_TASKS_Last_Week,
                                    Planned_TASKS_Last_Day=Planned_TASKS_Last_Day,
                                    Actual_TASKS_Last_Day=Actual_TASKS_Last_Day))
            FinalResponse.append(Performance.copy())
            try:
                Monthly_Performance = int((Actual_TASKS_Last_Month / Planned_TASKS_Last_Month) * 100)
            except ZeroDivisionError:
                Monthly_Performance = 0
            try:
                Weekly_Performance = int((Actual_TASKS_Last_Week / Planned_TASKS_Last_Week) * 100)
            except ZeroDivisionError:
                Weekly_Performance = 0
            return {"Monthly_Performance": Monthly_Performance,
                    "Weekly_Performance": Weekly_Performance}
            # return {"Performance": Performance, "Monthly_Performance": Monthly_Performance,
            #         "Weekly_Performance": Weekly_Performance}
    except Exception as E:
        if not Data:
            Response = {"responseCode": 400, "responseDescription": "Bad Request", "responsestate": "Fail"}
            return Response
        else:
            return {"respondecode": 500, "responseDescription": E}


# @a`pp.route("/Performance", methods=["POST"])
# def PerformanceTracker():
#     try:
#         Data = request.get_json()
#         if Data['jwt'] == "":
#             Response = {"responseCode": 400, "responseDescription": "Invalid Token", "responsestate": "Fail"}
#             return Response
#         EncodedJwt = Data['jwt']
#         DecodedJwt = jwt.decode(EncodedJwt, "secret", algorithms=["HS256"])
#         Mail = DecodedJwt['mail']
#         ProjectJson = []
#         Progress = []
#         FinalResponse = []
#         Total_Actual_Week = 0
#         Total_Planned_Week = 0
#         Total_Actual = 0
#         Total_Planned = 0
#         url = 'https://open.ortusolis.com/openproject/api/v3/users?filters=[{"login":{"operator":"=","values":["' + Mail + '"]}}]'
#         r = requests.get(url, auth=Key, params=TheParams)
#         j = r.json()
#         Data = j['_embedded']['elements']
#         Total_Planned_Month_Data = 0
#         Total_Actual_Month_Data = 0
#         Total_Planned_Week_Data = 0
#         Total_Actual_Week_Data = 0
#         Total_Planned_Last_Day_Data = 0
#         Total_Actual_Last_Day_Data = 0
#         for Value in Data:
#             Tasks = Link + str(Value['_links']['memberships']['href'])
#             # print("Tasks :", Tasks)
#             projects_memebrship = requests.get(Tasks, auth=Key)
#             k = projects_memebrship.json()
#             Data1 = k['_embedded']['elements']
#             for get_pro in Data1:
#                 try:
#                     project = get_pro['_links']['project']['title']
#                     planned_lastmonth = Link + str(get_pro['_links']['project'][
#                                                        'href']) + "/work_packages" + '?filters=[{"dueDate": {"operator": ">t-" ,"type": "date_past", "values":["30"]}}]'
#                     actual_lastmonth = Link + str(get_pro['_links']['project'][
#                                                       'href']) + "/work_packages" + '?filters=[{ "status": { "operator": "=","values":["13"]}},{"updatedAt": {"operator": ">t-" ,"type": "date_past", "values":["30"]}}]'
#                     planned_last_Week = Link + str(get_pro['_links']['project'][
#                                                        'href']) + "/work_packages" + '?filters=[{"dueDate": {"operator": ">t-" ,"type": "date_past", "values":["7"]}}]'
#                     actual_last_Week = Link + str(get_pro['_links']['project'][
#                                                       'href']) + "/work_packages" + '?filters=[{ "status": { "operator": "=","values":["13"]}},{"updatedAt": {"operator": ">t-" ,"type": "date_past", "values":["7"]}}]'
#                     planned_last_day = Link + str(get_pro['_links']['project'][
#                                                       'href']) + "/work_packages" + '?filters=[{"dueDate": {"operator": ">t-" ,"type": "date_past", "values":["1"]}}]'
#                     actual_last_day = Link + str(get_pro['_links']['project'][
#                                                      'href']) + "/work_packages" + '?filters=[{ "status": { "operator": "=","values":["13"]}},{"updatedAt": {"operator": ">t-" ,"type": "date_past", "values":["1"]}}]'
#                     project_Data = {
#                         "project": project,
#                         "planned_lastmonth": planned_lastmonth,
#                         "actual_lastmonth": actual_lastmonth,
#                         "planned_last_Week": planned_last_Week,
#                         "actual_last_Week": actual_last_Week,
#                         "planned_last_day": planned_last_day,
#                         "actual_last_day": actual_last_day
#                     }
#                     ProjectJson.append(project_Data)
#                 except KeyError:
#                     pass
#             for row in ProjectJson:
#                 planned_month = requests.get(row["planned_lastmonth"], auth=Key, params=TheParams)
#                 planned_Month_dat = planned_month.json()
#                 # print("planned_month :", planned_month)
#                 print("planned_Month_dat :", planned_Month_dat)
#                 try:
#                     planned_Month_Data = planned_Month_dat['_embedded']['elements']
#                     print("planned_Month_Data :", planned_Month_Data)
#                     for i in planned_Month_Data:
#                         try:
#                             if i['customField14'] is not None:
#                                 print("Total_Planned_Month_Data :", Total_Planned_Month_Data)
#                                 print("i['customField14'] :", i['customField14'])
#                                 Total_Planned_Month_Data = Total_Planned_Month_Data + i['customField14']
#                                 print("Total_Planned_Month_Data_AFTER :", Total_Planned_Month_Data)
#                         except KeyError:
#                             pass
#                 except KeyError:
#                     pass
#                 Actual_month = requests.get(row["actual_lastmonth"], auth=Key, params=TheParams)
#                 Actual_Month_dat = Actual_month.json()
#                 print("Actual_Month_dat :", Actual_Month_dat)
#                 try:
#                     Actual_Month_Data = Actual_Month_dat['_embedded']['elements']
#                     print("planned_Month_Data :", planned_Month_Data)
#                     for j in Actual_Month_Data:
#                         try:
#                             if j['customField14'] is not None:
#                                 print("Total_Actual_Month_Data :", Total_Actual_Month_Data)
#                                 print("j['customField14'] :", j['customField14'])
#                                 Total_Actual_Month_Data = Total_Actual_Month_Data + j['customField14']
#                                 print("Total_Actual_Month_Data_AFTER :", Total_Actual_Month_Data)
#                                 print("--------------------------------------------------------------")
#                         except KeyError:
#                             pass
#                 except KeyError:
#                     pass
#                 Total_Planned = Total_Planned + Total_Planned_Month_Data
#                 Total_Actual = Total_Actual + Total_Actual_Month_Data
#                 planned_Week = requests.get(row["planned_last_Week"], auth=Key, params=TheParams)
#                 planned_Week_dat = planned_Week.json()
#                 try:
#                     planned_Week_Data = planned_Week_dat['_embedded']['elements']
#                     for i in planned_Week_Data:
#                         try:
#                             if i['customField14'] is not None:
#                                 Total_Planned_Week_Data = Total_Planned_Week_Data + j['customField14']
#                         except KeyError:
#                             pass
#                 except KeyError:
#                     pass
#                 Actual_Week = requests.get(row["actual_last_Week"], auth=Key, params=TheParams)
#                 Actual_Week_dat = Actual_Week.json()
#                 try:
#                     Actual_Week_Data = Actual_Week_dat['_embedded']['elements']
#                     for i in Actual_Week_Data:
#                         try:
#                             if i['customField14'] is not None:
#                                 Total_Actual_Week_Data = Total_Actual_Week_Data + j['customField14']
#                         except KeyError:
#                             pass
#                 except KeyError:
#                     pass
#                 Total_Planned_Week = Total_Planned_Week + Total_Planned_Week_Data
#                 Total_Actual_Week = Total_Actual_Week + Total_Actual_Week_Data
#                 planned_last_day = requests.get(row["planned_last_day"], auth=Key, params=TheParams)
#                 planned_last_day_dat = planned_last_day.json()
#                 try:
#                     planned_Last_Day_Data = planned_last_day_dat['_embedded']['elements']
#                     for i in planned_Last_Day_Data:
#                         try:
#                             if i['customField14'] is not None:
#                                 Total_Planned_Last_Day_Data = Total_Planned_Last_Day_Data + j['customField14']
#                         except KeyError:
#                             pass
#                 except KeyError:
#                     pass
#                 actual_last_day = requests.get(row["actual_last_day"], auth=Key, params=TheParams)
#                 actual_last_day_dat = actual_last_day.json()
#                 try:
#                     actual_Last_Day_Data = actual_last_day_dat['_embedded']['elements']
#                     for i in actual_Last_Day_Data:
#                         try:
#                             if i['customField14'] is not None:
#                                 Total_Actual_Last_Day_Data = Total_Actual_Last_Day_Data + j['customField14']
#                         except KeyError:
#                             pass
#                 except KeyError:
#                     pass
#                 Progress.append(dict(project=row["project"], Total_Planned_Month_data=Total_Planned_Month_Data,
#                                      Total_Actual_Month_data=Total_Actual_Month_Data,
#                                      Total_Planned_Week_data=Total_Planned_Week_Data,
#                                      Total_Actual_Week_data=Total_Actual_Week_Data,
#                                      Total_Planned_Last_Day_Data=Total_Planned_Last_Day_Data,
#                                      Total_Actual_Last_Day_Data=Total_Actual_Last_Day_Data))
#             FinalResponse.append(Progress.copy())
#         try:
#             Monthly_Percentage = (Total_Actual / Total_Planned) * 100
#         except ZeroDivisionError:
#             Monthly_Percentage = 0
#         try:
#             Weekly_Percentage = (Total_Actual_Week / Total_Planned_Week) * 100
#         except ZeroDivisionError:
#             Weekly_Percentage = 0
#         return {"progress": Progress, "monthly_percentage": Monthly_Percentage, "weekly_percentage": Weekly_Percentage}
#     except Exception as E:
#         if not Data:
#             Response = {"responseCode": 400, "responseDescription": "Bad Request", "responsestate": "Fail"}
#             return Response
#         else:
#             return {"respondecode": 500, "responseDescription": E}


# @app.route("/allpoints", methods=["GET"])
# def AllPoints():
#     try:
#         Db = yaml.load(open('db.yaml'), Loader=FullLoader)
#         Cnx = mysql.connector.connect(host=Db['mysql_host'], user=Db['mysql_user'],
#                                       password=Db['mysql_password'], database=Db['mysql_db'],
#                                       auth_plugin=Db['mysql_auth'])
#         cursor = Cnx.cursor()
#         # cursor.execute(
#         #     """SELECT ROW_NUMBER() OVER(order by Total_Points desc) as Position , user.user_name, SUM(point.availed_points) AS Total_Points FROM user_details user LEFT JOIN points point
#         #     ON user.user_id= point.user_id Where user.Status='Active' GROUP BY user.user_id order by Total_Points asc""")
#         cursor.execute("""SELECT user.user_name, SUM(poi.availed_points) AS Total_Points FROM user_details user LEFT
#         JOIN points poi ON user.user_id= poi.user_id Where user.Status='Active' GROUP BY user.user_id order by
#         Total_Points asc""")
#         row_headers = [x[0] for x in cursor.description]  # this will extract row headers
#         rv = cursor.fetchall()
#         cursor.close()
#         var_fixed = []
#         for row in rv:
#             var_fixed.append(list(map(str, list(row))))
#         json_Data = []
#         for result in var_fixed:
#             json_Data.append(dict(zip(row_headers, result)))
#         for i in json_Data:
#             try:
#                 i['y'] = int(i['Total_Points'])
#             except ValueError:
#                 i['y'] = 0
#             del i['Total_Points']
#             i['label'] = i['user_name']
#             del i['user_name']
#             # print(json_Data)
#         return json.dumps({"All_points": json_Data})
#     except Exception as e:
#         return {"respondecode": 500, "responseDescription": e}



@app.route("/allpoints", methods=["POST"])
def AllPoints():
    try:
        Data = request.get_json()
        if Data['jwt'] == "":
            Response = {"responseCode": 400, "responseDescription": "Invalid Token", "responsestate": "Fail"}
            return Response
        EncodedJwt = Data['jwt']
        DecodedJwt = jwt.decode(EncodedJwt, "secret", algorithms=["HS256"])
        Mail = DecodedJwt['mail']

        Db = yaml.load(open('db.yaml'), Loader=FullLoader)
        Cnx = mysql.connector.connect(host=Db['mysql_host'], user=Db['mysql_user'],
                                      password=Db['mysql_password'], database=Db['mysql_db'],
                                      auth_plugin=Db['mysql_auth'])
        cursor = Cnx.cursor()
        cursor.execute("""SELECT ROW_NUMBER() OVER(order by Total_Points desc) as Position , user.user_name, 
        SUM(point.availed_points) AS Total_Points FROM user_details user LEFT JOIN points point ON user.user_id= 
        point.user_id Where user.Status='Active' GROUP BY user.user_id order by Total_Points asc""")
        row_headers = [x[0] for x in cursor.description]  # this will extract row headers
        rv = cursor.fetchall()
        cursor.close()
        var_fixed = []
        for row in rv:
            var_fixed.append(list(map(str, list(row))))
        json_Data = []
        for result in var_fixed:
            json_Data.append(dict(zip(row_headers, result)))
        for i in json_Data:
            try:
                i['Total_Points'] = int(i['Total_Points'])
            except ValueError:
                i['Total_Points'] = 0
        # print("json_Data :", json_Data)

        Db = yaml.load(open('db.yaml'), Loader=FullLoader)
        Cnx = mysql.connector.connect(host=Db['mysql_host'], user=Db['mysql_user'],
                                      password=Db['mysql_password'], database=Db['mysql_db'],
                                      auth_plugin=Db['mysql_auth'])
        cursor = Cnx.cursor()
        cursor.execute("""SELECT user_name FROM user_details Where Status='Active' and email = '%s' """ % Mail)
        rv = cursor.fetchall()
        cursor.close()
        var_fixed1 = []
        json_Data1 = []
        for row in rv:
            var_fixed1.append(list(map(str, list(row))))
        # print("json_Data1 :", json_Data1)
        # print(var_fixed1[0][0])
        for i in json_Data:
            if i['user_name'] == var_fixed1[0][0]:
                json_Data1.append(i)
                break
        return {"All_points": json_Data, "My_Points": json_Data1}
    except Exception as e:
        return {"respondecode": 500, "responseDescription": e}


@app.route("/RunScript", methods=["GET"])
def RunScript():
    try:
        calculation()
        criteriaCalculation()
        status = "success"
        code = 200
    except Exception as e:
        status = e
        code = 500
    return {"Responsecode": code, "ResponseStatus": status}


@app.route("/Rule_Insert", methods=["POST"])
def RuleInsert():
    try:
        Data = request.get_json()
        RuleName = Data['RuleName']
        RuleDesc = Data['RuleDesc']
        Occurrence = Data['Occurrence']
        RuleStartDate = Data['RuleStartDate']
        RuleEndDate = Data['RuleEndDate']
        isActive = Data['isActive']
        Project = Data['Project']
        # print("required Rule details is taken to check rules for existing")
        RuleStatus = rule_check(RuleName, RuleDesc, isActive, RuleStartDate, RuleEndDate, Occurrence, Project)
        RuleStatu = json.loads(RuleStatus)
        if RuleStatu['RuleStatus'] == "Rule already exists":
            return {"Responsecode": 200, "RuleId": RuleStatu['RuleId'], "RuleName": RuleName,
                    "RuleStatus": "Rule Already Exists"}
        else:
            RewardType = Data["RewardType"] # points, criteria, existing
            RewardTitle = Data["RewardTitle"] # badge, trophies, shields
            TaskType = Data["TaskType"] # task , bug, all
            RewardDesc = Data["RewardDesc"]
            RewardIcon = Data["RewardIcon"]
            ValidityStartDate = Data["ValidityStartDate"]
            ValidityEndDate = Data["ValidityEndDate"]
            RuleId = RuleStatu["RuleId"]
            if RewardTitle == "Badge":
                RewardId = "B" + str(RuleId)
            elif RewardTitle == "Trophy":
                RewardId = "T" + str(RuleId)
            elif RewardTitle == "Shield":
                RewardId = "S" + str(RuleId)
            else:
                RewardId = RewardTitle[:2] + str(RuleId)
            PointsOperator = Data["PointsOperator"]
            PointsStartDate = Data["PointsStartDate"]
            PointsEndDate = Data["PointsEndDate"]
            Point1 = Data["Point"]
            try:
                Point2 = Data["Point2"]
            except KeyError:
                Point2 = None
            # print("RuleID: ", RuleId)
            # print("RuleName: ", RuleName)
            # print("Point-1 :", Point1)

            if RuleId is None or RuleName is None or Point1 is None:
                Response = {"responseCode": 400, "responseDescription": "Invalid Details", "responsestate": "Fail"}
                return Response
            return reward_points(RewardType, RewardTitle, RewardDesc, RewardIcon, TaskType, ValidityStartDate, ValidityEndDate,
                                 RuleId, RewardId, PointsOperator, PointsStartDate, PointsEndDate,
                                 Point1, Point2, RuleName)
    except Exception as E:
        if not Data:
            Response = {"responseCode": 400, "responseDescription": "Bad Request", "responsestate": "Fail"}
            return Response
        else:
            return {"respondecode": 500, "responseDescription": E}


@app.route("/Projectslist", methods=["Get"])
def ProjectLists():
    try:
        Project_List = []
        url2 = 'https://open.ortusolis.com/openproject/api/v3/projects'
        Project = requests.get(url2, auth=Key, params=TheParams)
        Projects = Project.json()
        Data = Projects['_embedded']['elements']
        for Value in Data:
            project = Value['name']
            Project_List.append(project)
        return {"Responsecode": 200, "Projects": Project_List}
    except Exception as e:
        return {"respondecode": 500, "responseDescription": e}


@app.route("/User_Reward", methods=["GET"])
def UserReward():
    try:
        Db = yaml.load(open('db.yaml'), Loader=FullLoader)
        Cnx = mysql.connector.connect(host=Db['mysql_host'], user=Db['mysql_user'],
                                      password=Db['mysql_password'], database=Db['mysql_db'],
                                      auth_plugin=Db['mysql_auth'])
        cursor = Cnx.cursor()
        # cursor.execute(
        #     """DELETE t1 FROM UserRewards t1 INNER JOIN UserRewards t2 WHERE t1.UserRewardId < t2.UserRewardId
        #     AND t1.RewardsId = t2.RewardsId AND t1.UserId = t2.UserId AND t1.UserProject = t2.UserProject""")
        # cursor.commit()
        cursor.execute("SELECT UserRewards.UserId, user_details.user_name, UserRewards.UserProject, "
                       "Rewards.RewardTitle, RulesDef.TaskType, Rules.RuleName, Rules.RuleDesc, Rewards.RewardDes "
                       "FROM user_details, UserRewards, Rewards, RulesDef, Rules WHERE UserRewards.RewardsId = "
                       "Rewards.RewardsId AND Rewards.RuleDefId = RulesDef.RulesDefId AND RulesDef.RuleId = "
                       "Rules.RuleId AND user_details.user_id = UserRewards.UserId ")
        row_headers = [x[0] for x in cursor.description]  # this will extract row headers
        rv = cursor.fetchall()
        cursor.close()
        var_fixed = []
        for row in rv:
            var_fixed.append(list(map(str, list(row))))
        json_Data = []
        for result in var_fixed:
            json_Data.append(dict(zip(row_headers, result)))
        return {"AllUserBadges": json_Data}
    except Exception as e:
        return {"respondecode": 500, "responseDescription": e}


@app.route("/User_Reward_Individual", methods=["POST"])
def userRewardsIndividual():
    try:
        Data = request.get_json()
        EncodedJwt = Data['jwt']
        DecodedJwt = jwt.decode(EncodedJwt, "secret", algorithms=["HS256"])
        Mail = DecodedJwt['mail']
        TodayDate = datetime.today().strftime('%Y-%m-%d')
        Db = yaml.load(open('db.yaml'), Loader=FullLoader)
        Cnx = mysql.connector.connect(host=Db['mysql_host'], user=Db['mysql_user'],
                                      password=Db['mysql_password'], database=Db['mysql_db'],
                                      auth_plugin=Db['mysql_auth'])
        cursor = Cnx.cursor()
        sql = "SELECT UserRewards.UserID, user_details.user_name, UserRewards.RewardsID, Rewards.RewardTitle, " \
              "Rules.RuleName, Rewards.RewardDes, UserRewards.Reward_gained_date , Rewards.ValidityStart, " \
              "Rewards.ValidityEnd FROM UserRewards JOIN user_details ON user_details.user_id = UserRewards.UserID " \
              "JOIN Rewards ON Rewards.RewardsId = UserRewards.RewardsId JOIN Rules WHERE user_details.Status IS NOT " \
              "NULL AND Rewards.ValidityEnd <= %s AND user_details.email = %s "
        value = (TodayDate, Mail)
        cursor.execute(sql, value)
        row_headers = [x[0] for x in cursor.description]  # this will extract row headers
        rv = cursor.fetchall()
        cursor.close()
        var_fixed = []
        for row in rv:
            var_fixed.append(list(map(str, list(row))))
        json_Data = []
        for result in var_fixed:
            json_Data.append(dict(zip(row_headers, result)))
        return {"userBadges": json_Data}
    except Exception as e:
        return {"respondecode": 500, "responseDescription": e}


@app.route("/Rule_Insert_Criteria", methods=["POST"])
def RuleInsertCriteria():
    try:
        Data = request.get_json()
        RuleName = Data['RuleName']
        RuleDesc = Data['RuleDesc']
        isActive = Data['isActive']
        RuleStartDate = Data['RuleStartDate']
        RuleEndDate = Data['RuleEndDate']
        Occurrence = Data['Occurrence']
        Project = Data['Project']
        RuleStatus = rule_check(RuleName, RuleDesc, isActive, RuleStartDate, RuleEndDate, Occurrence, Project)
        RuleStatu = json.loads(RuleStatus)
        if RuleStatu["RuleStatus"] == 'Rule already exists':
            return {"Responsecode": 200, "RuleId": RuleStatu['RuleId'], "RuleName": RuleName,
                    "RuleStatus": "Rule Already Exists"}
        else:
            RewardType = Data["RewardType"]
            RewardTitle = Data["RewardTitle"]
            TaskType = Data["TaskType"]
            RewardDesc = Data["RewardDesc"]
            RewardIcon = Data["RewardIcon"]
            validitystart = Data["validitystart"]
            validityend = Data["validityend"]
            RuleId = RuleStatu["RuleId"]
            if RewardTitle == "Badge":
                RewardId = "B" + str(RuleId)
            elif RewardTitle == "Trophy":
                RewardId = "T" + str(RuleId)
            elif RewardTitle == "Shield":
                RewardId = "S" + str(RuleId)
            else:
                RewardId = RewardTitle[:2] + str(RuleId)
            if RewardType == "Criteria":
                PointsStartDate = Data["CriteriaStartDate"]
                PointsEndDate = Data["CriteriaEndDate"]
                Priority = Data["Priority"]
                PriorityOperator = Data["PriorityOperator"]
                if TaskType == "Task":
                    Complexity = Data["Complexity"]
                    Complexity_operator = Data["Complexity_operator"]
                elif TaskType == "Bug":
                    Complexity = Data["Defect"]
                    Complexity_operator = Data["Defect_operator"]
                elif TaskType == "All":
                    Complexity = ""
                    Complexity_operator = ""
                ScheduleOperator = Data["ScheduleOperator"]
                ScheduleMin = Data["ScheduleMin"]
                ScheduleMax = Data["ScheduleMax"]
                EffortOperator = Data["EffortOperator"]
                EffortMin = Data["EffortMin"]
                EffortMax = Data["EffortMax"]
                NumberOfTasks1 = Data["NumberOfTasks1"]
                NumberOfTasks2 = Data["NumberOfTasks2"]
                NumberOfTasksOperator = Data["NumberOfTasksOperator"]
                return reward_criteria(RuleName, RewardType, NumberOfTasks2, NumberOfTasks1, NumberOfTasksOperator,
                                       RewardTitle, RewardDesc, RewardIcon, TaskType,
                                       validitystart, validityend, RuleId, RewardId, PointsStartDate, PointsEndDate,
                                       Priority, PriorityOperator, Complexity, Complexity_operator, ScheduleOperator,
                                       ScheduleMin, ScheduleMax, EffortOperator, EffortMin, EffortMax)
    except Exception as e:
        return {"respondecode": 500, "responseDescription": e}


# @app.route("/Existing_Rewards", methods=["POST"])
# def ExistingRewards():
#     try:
#         Data = request.get_json()
#         RuleStartDate = Data['RuleStartDate']
#         RuleEndDate = Data['RuleEndDate']
#         ValidityStartDate = Data['validitystart']
#         ValidityEndDate = Data['validityend']
#         Project = Data['Project']
#         reward1 = Data['reward1']
#         reward2 = Data['reward2']
#         reward3 = Data['reward3']
#         reward4 = Data['reward4']
#         reward5 = Data['reward5']
#         reward6 = Data['reward6']
#         existing_reward = reward_existing(RuleStartDate, RuleEndDate, ValidityStartDate, ValidityEndDate, Project,
#                                           reward1, reward2, reward3, reward4, reward5, reward6)
#     return existing_reward


# @app.route("/Existing_Rewards", methods=["POST"])
# def ExistingRewards():
#     try:
#         Data = request.get_json()
#         RuleStartDate = Data['RuleStartDate']
#         RuleEndDate = Data['RuleEndDate']
#         ValidityStartDate = Data['validitystart']
#         ValidityEndDate = Data['validityend']
#         Project = Data['Project']
#         # Occurrence = Data['Occurrence']
#         # RuleName = Data['RuleName']
#         # RuleDesc = Data['RuleDesc']
#         # isActive = Data['isActive']
#         # RuleStatus = rule_check(RuleName, RuleDesc, isActive, RuleStartDate, RuleEndDate, Occurrence, Project)
#         # RuleStatu = json.loads(RuleStatus)
#         if RuleStatu['RuleStatus'] == "Rule already exists":
#             return {"Responsecode": 200, "RuleId": RuleStatu['RuleId'], "RuleName": RuleName,
#                     "RuleStatus": "Rule Already Exists"}
#         else:
#             RuleId = RuleStatu["RuleId"]
#             PointsStartDate = Data["PointsStartDate"]
#             PointsEndDate = Data["PointsEndDate"]
#             TaskType = Data["TaskType"]
#             RewardType = Data["RewardType"]
#             RewardTitle = Data["RewardTitle"]
#             if RewardTitle == "Badge":
#                 RewardId = "B" + str(RuleId)
#             elif RewardTitle == "Trophy":
#                 RewardId = "T" + str(RuleId)
#             elif RewardTitle == "Shield":
#                 RewardId = "S" + str(RuleId)
#             else:
#                 RewardId = RewardTitle[:2] + str(RuleId)
#             RewardDesc = Data["RewardDesc"]
#             RewardIcon = Data["RewardIcon"]
#             validitystart = Data["validitystart"]
#             validityend = Data["validityend"]
#             if RuleId is None or RuleName is None:
#                 Response = {"responseCode": 400, "responseDescription": "Invalid Details", "responsestate": "Fail"}
#                 return Response
#             return reward_existing(RewardType, RewardTitle, RewardDesc, RewardIcon, TaskType, validitystart, validityend,
#                                  RuleId, RewardId, PointsStartDate, PointsEndDate, RuleName)
#     except Exception as E:
#         if not Data:
#             Response = {"responseCode": 400, "responseDescription": "Bad Request", "responsestate": "Fail"}
#             return Responsea
#         else:
#             return {"respondecode": 500, "responseDescription": E}


if __name__ == "__main__":
    app.run(threaded=True, port=5000, host="127.0.0.1")
