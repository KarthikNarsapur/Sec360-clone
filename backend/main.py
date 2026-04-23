import json
from dotenv import load_dotenv
from fastapi import FastAPI, Query, File, UploadFile, Form, Depends, Request
from fastapi.responses import JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi import WebSocket
from starlette.middleware.base import BaseHTTPMiddleware
import gzip
import io
from fastapi.middleware.gzip import GZipMiddleware

from utils.framework_scan import run_framework_scan


# --- Load environment variables ---
load_dotenv()

# --- Initialize FastAPI app ---
app = FastAPI(title="Sec360 Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth middleware
# from Auth.auth_middleware import AuthMiddleware
# app.add_middleware(AuthMiddleware)

app.add_middleware(GZipMiddleware, minimum_size=500)

# Import utility
from utils.upload_to_s3 import get_report_from_s3_function
from word_report_generator.generate_report_word import get_report_word_function
from word_report_generator.awafr_report import get_awarf_report_word_function
from utils.scan import run_scan
from utils.chatbot import get_chatbot
from utils.send_mail import send_mail_function
from utils.list_vpc_flow_logs import get_vpc_flow_logs_function
from utils.util import validate_ip_function
from utils.site24x7_service import (
    get_site24x7_dashboard_list_function,
    add_site24x7_dashboard_function,
    get_site24x7_settings_function,
    update_site24x7_settings_function,
)


# Import modules
from ML.VpcFlowLogs.vpcflowlogs_findings import get_VPC_flow_log_findings
from ML.Cloudtrail.cloudtrail_findings import get_cloudtrail_findings


from Auth.model import (
    UserModel,
    ConfirmUserModel,
    ResendCodeUserModel,
    LoginUserModel,
    GetUserDetailsModel,
    ResetPasswordModel,
)
from db.model import UserDataModel, DBKeysModel, RolesInfoModel, UpdateProfileModel
from Model.model import (
    AccessTokenModel,
    UserQueryModel,
    DateRangeModel,
    CISRuleScanModel,
    ListEKSClusterModel,
    RunScriptRequest,
    UserNameModel,
    ReportRequest,
    PDFReportModel,
    ContactFormModel,
    WebsiteScanModel,
)


from Auth.controller import (
    get_all_users,
    sign_up_function,
    confirm_user_function,
    resend_code_function,
    login_function,
    get_user_function,
    forgot_password_function,
    reset_password_function,
    get_user_account_details_function,
)
from db.crud import (
    add_userdata_function,
    get_userdata_function,
    add_roleinfo_function,
    update_roleinfo_function,
    get_user_profile_details_function,
    delete_role_data_function,
    get_eks_accounts_details_function,
    get_pdf_report_function,
    update_user_profile_function,
)

from modules.CIS.cis_run_checks import cis_rules_scan_function, websocket_manager
from modules.ISO.iso_run_checks import iso_rules_scan_function

# from modules.NIST.nist_run_checks import nist_rules_scan_function
from modules.AWAF.awaf_run_checks import awaf_rules_scan_function
from modules.kubernetes.kubernetes_checks import list_eks_clusters
from modules.kubernetes.Run_Scripts.tool_setup import (
    kubernetes_tool_setup_function,
    kubernetes_websocket_manager,
)
from utils.framework_scan import run_framework_scan
from modules.Website.OWASP.owasp_run_checks import owasp_scan_function

from utils.logger import logger


@app.get("/api/check")
def check_backend():
    logger.info("Health check endpoint hit")
    logger.warning("this is a warning log test message")
    return {
        "status": "ok",
        "message": "Backend is running",
    }


@app.get("/api/secure-check")
def secure_check(request: Request):
    user = request.scope.get("user")
    if not user:
        return {"error": "User not found in request (middleware may not have run)"}

    return {"status": "ok", "message": "Secure route access granted", "user": user}


@app.get("/api/validate-ip")
def validate_ip(request: Request):
    return validate_ip_function(request)


@app.get("/api/site24x7-dashboard")
def get_site24x7_dashboard_list(request: Request):
    return get_site24x7_dashboard_list_function(request)


@app.post("/api/site24x7-dashboard/add")
def add_dashboard(request: Request, payload: dict):
    return add_site24x7_dashboard_function(request, payload)


@app.get("/api/site24x7/settings")
def get_settings(request: Request):
    return get_site24x7_settings_function(request)


@app.post("/api/site24x7/settings/update")
def update_settings(request: Request, payload: dict):
    return update_site24x7_settings_function(request, payload)


@app.post("/api/contact-us")
def send_contact_mail(request: ContactFormModel):
    return send_mail_function(request)


# Auth
@app.post("/api/signup")
def signUp(user: UserModel):
    return sign_up_function(user)


@app.post("/api/confirmsignup")
def confirmUser(confirm_user: ConfirmUserModel, user: UserDataModel):
    return confirm_user_function(confirm_user=confirm_user, user=user)


@app.post("/api/resendcode")
def resendCode(resend_code_user: ResendCodeUserModel):
    return resend_code_function(resend_code_user)


@app.post("/api/login")
def login(login_user: LoginUserModel):
    return login_function(login_user)


@app.post("/api/getuser")
def getUser(get_user: GetUserDetailsModel):
    return get_user_function(get_user)


@app.post("/api/getuseraccount")
def getUserAccount(get_user: GetUserDetailsModel):
    return get_user_account_details_function(get_user)


@app.post("/api/forgotpassword")
def forgotPassword(forgot_password: ResendCodeUserModel):
    return forgot_password_function(forgot_password)


@app.post("/api/resetpassword")
def resetPassword(reset_password: ResetPasswordModel):
    return reset_password_function(reset_password)


# Database
@app.post("/api/adduserdata")
def addUser(userdata: UserDataModel):
    return add_userdata_function(userdata)


@app.post("/api/getuserdata")
def getUser(userdata: DBKeysModel):
    return get_userdata_function(userdata)


@app.post("/api/saveroleinfo")
def saveRoleInfo(rolesinfo: RolesInfoModel):
    return add_roleinfo_function(rolesinfo)


@app.post("/api/updaterole")
def updateRoleInfo(rolesinfo: RolesInfoModel):
    return update_roleinfo_function(rolesinfo)


@app.post("/api/getprofile")
def getUserProfile(get_user: GetUserDetailsModel):
    return get_user_profile_details_function(get_user)


@app.post("/api/updateprofile")
def updateProfile(update_data: str = Form(...), profile_image: UploadFile = File(None)):
    update_data = UpdateProfileModel(**json.loads(update_data))
    return update_user_profile_function(
        update_data=update_data, profile_image=profile_image
    )


@app.post("/api/deleterole")
def deleteRoleData(role_data: RolesInfoModel):
    return delete_role_data_function(role_data)


# scan
@app.post("/api/scan")
def scanAccounts(data: AccessTokenModel):
    return run_scan(data)


@app.post("/api/get-report")
def getReport(data: ReportRequest):
    return get_report_from_s3_function(data)


@app.post("/api/get-report-word")
def getWordReport(data: ReportRequest):
    return get_report_word_function(data)


@app.post("/api/get-report-word/awafr")
def getWordReportAWAFR(data: ReportRequest):
    return get_awarf_report_word_function(data)


@app.post("/api/get-report-excel/best-practice")
def getExcelReportBestPractice(data: ReportRequest):
    return get_best_practice_report_excel_function(data)


@app.post("/api/list-vpc-flow-logs")
def listVPCFlowLogs(data: AccessTokenModel):
    return get_vpc_flow_logs_function(data)


@app.post("/api/scanvpc")
def scanAccountsVPCFlowLogs(data: AccessTokenModel):
    return get_VPC_flow_log_findings(data)


@app.post("/api/scancloudtrail")
def scanAccountsCloudtrailLogs(data: AccessTokenModel):
    return get_cloudtrail_findings(data)


@app.post("/api/cisscan")
async def scanCISRules(data: AccessTokenModel):
    return await cis_rules_scan_function(data)


@app.post("/api/iso-scan")
async def scanISORules(data: AccessTokenModel):
    return await iso_rules_scan_function(data)


# @app.post("/api/nist-scan")
# async def scanNISTRules(data: AccessTokenModel):
#     return await nist_rules_scan_function(data)


@app.post("/api/awaf-scan")
async def scanAWAFRules(data: AccessTokenModel):
    return await awaf_rules_scan_function(data)


@app.post("/api/rbi-scan")
async def scanRBIRules(data: AccessTokenModel):
    return run_framework_scan(data, framework="rbi")


@app.post("/api/sebi-scan")
async def scanSEBIRules(data: AccessTokenModel):
    return run_framework_scan(data, framework="sebi")

@app.post("/api/dpdp-scan")
async def scanDPDPRules(data: AccessTokenModel):
    return run_framework_scan(data, framework="dpdp")


@app.post("/api/website-scan/owasp")
async def scanWebsite(data: WebsiteScanModel):
    return await owasp_scan_function(data)


@app.post("/api/chatbot")
def getChatbotConversation(user_query: UserQueryModel):
    return get_chatbot(user_query)


@app.websocket("/ws/cis-progress")
async def websocket_cis_progress(websocket: WebSocket):
    await websocket_manager(websocket)


# kubernetes
@app.post("/api/listeksclusters")
def listAllEKS(getEks: ListEKSClusterModel):
    return list_eks_clusters(getEks)


@app.post("/api/setup-kubernetes-tool")
async def setupKubernetesTool(data: RunScriptRequest):
    return await kubernetes_tool_setup_function(data)


@app.websocket("/ws/kubernetes-script-logs")
async def websocket_kubernetes_script_logs(
    websocket: WebSocket, session_id: str = Query(...)
):
    await kubernetes_websocket_manager(websocket, session_id)


@app.post("/api/get-eks-accounts")
def getUserEKSDetails(data: UserNameModel):
    return get_eks_accounts_details_function(data)


@app.post("/api/get-report-pdf")
def get_pdf_report(data: PDFReportModel):
    return get_pdf_report_function(data)
