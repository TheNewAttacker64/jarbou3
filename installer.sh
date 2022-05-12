
wget -q --spider http://google.com

if [ $? -eq 0 ]; then
    echo "[+] Found Internet Acces"
    sleep 1
else
    echo "[-] Check your Internet"
    exit
fi
echo "[*] Installing Server Req"
pip3 install -r req.txt
if which wine curl >/dev/null; then
    echo "[+] Wine and curl Already Installed"
else
    echo "[*] Installing Wine and curl"
    sudo apt install wine curl
fi
echo "[*] Installing python for wine"
curl https://www.python.org/ftp/python/3.10.4/python-3.10.4-amd64.exe -o python.exe >/dev/null

echo "[*] Choose windows10 Config"
winecfg
wine python.exe

echo "[*] Installing Req"

wine pip install -r req.txt
wine pip uninstall typing

echo "Now the C&C server ,If you face any issue pls feel free to report it"
sleep 2


