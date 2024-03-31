import shutil

import win32api
import win32con
import argparse

watcher_dl = False

# C:\Users\Temper\AppData\Local\Programs\Python\Python38\Scripts\pyinstaller.exe -D main.py -w --uac-admin --hiddenimport tensorflow -i r.ico --version-file file_v.txt --noconfirm
#  --contents-directory .

import sys
import ctypes
import time
import random
'''
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


if is_admin():
    pass
else:
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
    sys.exit()
'''



'''
rdn1 = int(input('Hezhong Dev Version, Please Input Key1:'))
rdn2 = int(input('Hezhong Dev Version, Please Input Key2:'))
rdn3 = int(input('Hezhong Dev Version, Please Input Key3:'))

Start Key:





def pad_number(input_num, seed):
    random.seed(seed)
    num_str = str(input_num)
    while len(num_str) < 12:
        num_str += str(random.randint(0, 9))
    return int(num_str)


random.seed(rdn2)
tkey = pad_number(abs(round(
    round(round(rdn1 / rdn2) * (round(rdn2 / rdn1) * rdn1 / (rdn2 / random.randint(10000, 99999)))) * round(
        (rdn1 / random.randint(100000, 999999))) * 213 / 8133) - 984 + 371), rdn1)

if tkey == rdn3:
    print('Key is OK!Start Software!')
else:
    print('Error Key!')
    input()
    exit()
'''
import os

os.environ["MKL_NUM_THREADS"] = '4'
os.environ["NUMEXPR_NUM_THREADS"] = '4'
os.environ["OMP_NUM_THREADS"] = '4'
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

import PyQt5
import base64
import hashlib
import os.path
import string
import logging

sys.setrecursionlimit(10000)
import pefile
import sys
import threading
import tkinter as tk
from PyQt5.QtCore import QThread, pyqtSignal, pyqtSlot, QTimer
import pystray
import requests  # 导入库
import PyQt5.QtWidgets as qtw
from PyQt5 import QtCore
from PyQt5.QtCore import QEventLoop, QCoreApplication
from PyQt5.QtGui import QIcon
from watchdog.events import *
import psutil
import wx
import yara
import pandas
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from UI.untitled import Ui_MainWindow as lobbywindow
from UI.scan import Ui_Form as scanform
from UI.set import Ui_Form as setfrom
from UI.about import Ui_Form as abofrom
from configparser import ConfigParser
from UI.update import Ui_Form as updatefrom
from UI.geli import Ui_Form as glfrom
from PIL import Image
from keras.models import load_model
import gc
from preprocess import preprocess
import numpy
import at
from pedb import hz_funcs
import tensorflow as tf

# 隐藏所有GPU设备
physical_devices = tf.config.list_physical_devices('GPU')
if len(physical_devices) > 0:
    tf.config.set_visible_devices([], 'GPU')

global watchmbra
global watchreg

global setfrom
global MainWindow
global heurtttts
global app11
global scan_skip_big_file
import re
# 定义变量

from configparser import ConfigParser


global mainui
global scanwindow


def writecfg(datatext, xx, xx2):
    config = ConfigParser()
    config.set(xx, xx2, datatext)
    with open('cfg.ini', 'w') as configfile:
        config.write(configfile)


def virusnamedecode(name):
    if name == 'None' or name is None:
        return False
    try:
        if 'HezhongRule' in name:
            n = ''
            for i in name.split('_'):
                if i == 'HezhongRule':
                    pass

                else:
                    n += f'{i}.'

            return n[:-1]
        elif 'MALWARE' in name:
            yui1 = name.split('_')[2]
            if 'Redline' in name:
                return 'Spyware.RedlineSteal..'
            elif 'Stealer' in name:
                if 'Multi' in name:
                    return 'Spyware.MultSteal!{}'.format(yui1)
                return 'Spyware.Steal!{}'.format(yui1)
            elif 'Multi' in name:
                return 'Trojan.Mult!{}'.format(yui1)
            else:
                return 'Trojan.{}.'.format(yui1)

        elif 'Windows' or 'Linux' in name:
            if 'Linux' in name:
                yui2 = 'Linux.' + name.split('_')[1]
            else:
                yui2 = name.split('_')[1]
            yui23 = name.split('_')[2]
            yui233 = name.split('_')[3]
            if yui2 == 'Ransomware':
                yui2 = 'Ransom'
            if yui23 == 'CobaltStrike':
                yui2 = 'BackDoor'
            return '{}.{}.{}'.format(yui2, yui23, yui233)
        else:
            if 'Trojan' in name:
                if 'MSIL' in name:
                    if 'RAT' or 'rat' in name:
                        return 'MSIL:Backdoor.Generic'
                    return 'MSIL:Trojan.Generic'
                elif 'APT' in name:
                    if 'RAT' or 'rat' in name:
                        return 'APT:Backdoor.Generic'
                    return 'APT:Trojan.Generic'
                else:
                    return 'Trojan.Generic'
            elif 'HackTool' in name:
                if 'MSIL' in name:
                    return 'MSIL:HackTool.Generic'
                elif 'APT' in name:
                    return 'APT:HackTool.Generic'
                else:
                    return 'HackTool.Generic'
            elif 'Dropper' in name:
                if 'APT' in name:
                    return 'APT:TrojanDrop.Generic'
                else:
                    return 'TrojanDrop.Generic'
            elif 'Loader' in name:
                if 'APT' in name:
                    return 'APT:TrojanLoad.Generic'
                else:
                    return 'TrojanLoad.Generic'
            elif 'Backdoor' in name:
                if 'APT' in name:
                    return 'APT:Backdoor.Generic'
                else:
                    return 'Backdoor.Generic'
            else:
                if 'MSIL' in name:
                    return 'MSIL:Malware.Generic'
                else:
                    return 'NH:Malware.Gen'
    except:
        return 'NH:Malware.Gen'


def softwareexit():
    global app11
    app11.quit()


def softwest():
    global MainWindow
    MainWindow.show()


def softwaretp():
    menu = (
        pystray.MenuItem(text='显示界面', action=softwest),
        pystray.MenuItem(text='退出', action=softwareexit),
    )
    image = Image.open("r.ico")
    icon = pystray.Icon("HeZhong", image, "河众", menu)

    threading.Thread(target=icon.run, daemon=True).start()


class VirusScan:
    def __init__(self):
        pass



    def predict(self, model, fn_list, label, filedata, batch_size=1, verbose=0):
        max_len = model.input.shape[1]

        sequence, _ = preprocess(fn_list, max_len, filedata)

        if sequence is not None:
            pred = model.predict(numpy.array([sequence]), verbose=0)
            return pred
        else:
            print("File preprocessing failed.")
            return None

    def yarascan(self, rule, file, fdb):
        matches = rule.match(data=fdb)
        if len(matches) > 0:
            return matches

    def getrules(self, rulepath):
        filepath = {}
        for index, file in enumerate(os.listdir(rulepath)):
            rupath = os.path.join(rulepath, file)
            key = "rule" + str(index)
            filepath[key] = rupath
        yararule = yara.compile(filepaths=filepath)
        return yararule

    def md5_scan(self, path, database, fdb):
        print(path)
        file_md5 = hashlib.md5(fdb).hexdigest()
        if file_md5 in database:
            return ['Malware.Gen', file_md5]
        else:
            return [False, file_md5]

    def cscan(self, md5):
        try:
            dat = f'-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="md5s"\r\n\r\n{md5}\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="format"\r\n\r\nXML\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="product"\r\n\r\n360zip\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="combo"\r\n\r\n360zip_main\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="v"\r\n\r\n2\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="osver"\r\n\r\n5.1\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="vk"\r\n\r\na03bc211\r\n-------------------------------7d83e2d7a141e\r\nContent-Disposition: form-data; name="mid"\r\n\r\n8a40d9eff408a78fe9ec10a0e7e60f62\r\n-------------------------------7d83e2d7a141e--'
            r = requests.post('http://qup.f.360.cn/file_health_info.php', data=dat, timeout=3)
            print(r.text)
            return r.status_code == 200 and float(re.findall('<e_level>(.*?)</e_level>', r.text, re.S)[0]) > 50
        except:
            return False

    def pescan(self, db, peo):
        try:
            pefunc = []
            for entry in peo.DIRECTORY_ENTRY_IMPORT:
                for func in entry.imports:
                    try:
                        pefunc.append(str(func.name, "utf-8"))
                    except:
                        pass
            return pefunc in db

        except:
            return False


def loadprotect():
    pass


global pe


def proess_watcher_scaner(seter, whitedb, rules, sc, model, proc=None, path=None, mot=False):
    try:
        global watcher_dl
        # print(path)
        if not mot:
            path = proc.exe()
            pid = proc.info['pid']
        else:
            pass
        if os.path.getsize(path) > 20000000:
            return 0
        with open(path, 'rb') as f:
            filda = f.read()
        clouduse = seter['scan']['cloud']
        yaruse = seter['scan']['yara']
        mluse1 = seter['scan']['heur']
        dlw = seter['setting']['dlw']
        if (dlw == 'True' or dlw is True) and (mluse1 == 'True' or mluse1 is True):
            mluse = 'True'
        else:
            mluse = 'False'
        # print(mluse)
        vr1 = VirusScan.md5_scan(sc, path, md5_watchdatabase, filda)
        virusname1 = vr1[0]


        if vr1[1] in whitedb:
            return 0

        if virusname1:
            threading.Thread(target=show_noti, args=[process_string(path, 50), virusname1], daemon=True).start()
            if not mot:
                proc.kill()
            time.sleep(0.1)
            i = 0
            while True:
                i += 1
                filename = str(i) + ".tro"
                filepath = os.path.join('./Malwaregl', filename)
                if not os.path.exists(filepath):
                    lastf = filepath
                    break
            fb = base64.b64encode(filda)
            filenumber = os.path.basename(lastf)
            with open('{}'.format(lastf), 'wb') as f:
                f.write(fb)
            with open('./Malwaregl/{}.ini'.format(filenumber), 'w', encoding='utf-8') as f:
                f.write(path)
            os.remove(path)
            return 0
        if yaruse == 'True' or yaruse is True:
            # print('Yara Scan')

            yaa = VirusScan.yarascan(sc, rules, path, filda)
            if yaa is None or yaa == 'None':
                pass
            else:
                yaa2 = virusnamedecode(str(yaa[0]))
                threading.Thread(target=show_noti, args=[process_string(path, 50), yaa2], daemon=True).start()
                if not mot:
                    proc.kill()
                i = 0
                while True:
                    i += 1
                    filename = str(i) + ".tro"
                    filepath = os.path.join('./Malwaregl', filename)
                    if not os.path.exists(filepath):
                        lastf = filepath
                        break
                fb = base64.b64encode(filda)
                filenumber = os.path.basename(lastf)
                with open('{}'.format(lastf), 'wb') as f:
                    f.write(fb)

                with open('./Malwaregl/{}.ini'.format(filenumber), 'w', encoding='utf-8') as f:
                    f.write(path)

                os.remove(path)
                return 0
        if clouduse == 'True' or clouduse is True:
            # print('Cloud Scan')
            if VirusScan.cscan(sc, vr1[1]):
                threading.Thread(target=show_noti, args=[process_string(path, 50), 'Malware.Gen(qc)'],
                                         daemon=True).start()
                if not mot:
                    proc.kill()
                i = 0
                while True:
                    i += 1
                    filename = str(i) + ".tro"
                    filepath = os.path.join('./Malwaregl', filename)
                    if not os.path.exists(filepath):
                        lastf = filepath
                        break
                fb = base64.b64encode(filda)
                os.remove(path)
                filenumber = os.path.basename(lastf)
                with open('{}'.format(lastf), 'wb') as f:
                    f.write(fb)

                with open('./Malwaregl/{}.ini'.format(filenumber), 'w', encoding='utf-8') as f:
                    f.write(path)
                return 0
        # print(mluse)
        if mluse == 'True' or mluse is True:
            try:
                pe_rule = '''
                rule PE
                {
                    meta:
                        author = "Hezhong Technology"
                    condition:
                        uint16(0) == 0x5a4d
                }
                '''
                rulePE = yara.compile(source=pe_rule)
                isPE = rulePE.match(data=filda)

                if isPE != []:
                    flabels = numpy.zeros((1,))
                    pred1 = VirusScan.predict(sc, model, path, flabels, filda, 16, 0)
                    pred = pred1[0][0]
                    try:
                        if pred >= 0.9:
                            ml_virusname = 'DL.Trojan.{}.a'.format(round(pred * 100))
                        elif pred >= 0.8:
                            ml_virusname = 'DL.Trojan.{}.b'.format(round(pred * 100))
                        elif pred >= 0.7:
                            ml_virusname = 'DL.Trojan.{}.c'.format(round(pred * 100))
                        else:
                            ml_virusname = None
                    except IndexError:
                        ml_virusname = None
                    print(ml_virusname)
                    if ml_virusname is not None:
                        print('Start Thread!')
                        threading.Thread(target=show_noti, args=[process_string(path, 50), ml_virusname],
                                         daemon=True).start()
                        if not mot:
                            proc.kill()
                        i = 0
                        while True:
                            i += 1
                            filename = str(i) + ".tro"
                            filepath = os.path.join('./Malwaregl', filename)
                            if not os.path.exists(filepath):
                                lastf = filepath
                                break
                        fb = base64.b64encode(filda)
                        filenumber = os.path.basename(lastf)
                        with open('{}'.format(lastf), 'wb') as f:
                            f.write(fb)

                        with open('./Malwaregl/{}.ini'.format(filenumber), 'w', encoding='utf-8') as f:
                            f.write(path)

                        os.remove(path)
                        return 0
                else:
                    pass
            except:
                pass
            # def predict(self, model, fn_list, label, filedata, batch_size=1, verbose=0):





        return 0
    except Exception as ff:
        print(ff)






def proess_watcher():
    sc = VirusScan()
    global md5_watchdatabase
    with open('./bd/bd.vdb') as f:
        md5_watchdatabase = f.read()
    with open('bd/white.data') as f:
        whitedb = f.read()
    seter = ConfigParser()
    seter.read('cfg.ini')
    model = load_model('./bd/hzml.h5')

    yararule_co2 = VirusScan.getrules(sc, './bd/yara')
    running_pross1 = []
    running_pross2 = []
    while 1:
        time.sleep(0.01)
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.info['pid']
                path = proc.exe()
                if pid in running_pross1 and path in running_pross2:
                    continue
            except:
                pass
            time.sleep(0.01)
            if prosswa is False:
                print('停止进程监控！')
                return 0

            try:
                pid = proc.info['pid']
                path = proc.exe()
                running_pross2.append(path)
                running_pross1.append(pid)
                # print('Scan!')
                threading.Thread(target=proess_watcher_scaner,
                                 args=[seter, whitedb, yararule_co2, sc, model, proc, None, False]).start()


            except Exception:
                pass


def monitor_files(path):
    global ProtectF
    global md5_watchdatabase
    with open('bd/bd.vdb') as f:
        md5_watchdatabase = f.read()
    observer = Observer()
    event_handler = Watch_FileMonitor()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    while True:
        time.sleep(1)
        if ProtectF is False:
            print('停止监控！')
            observer.stop()
            break


def process_string(s, a):
    # 检查字符串长度是否大于20
    if len(s) > a:
        # 如果大于50，则保留前20位和后20位，并用省略号连接
        return s[:15] + "..." + s[-15:]
    else:
        # 如果小于或等于50，则原样返回
        return s


def runwatcher():
    global ProtectB
    disk_list = []
    thread_t = []
    for c in string.ascii_uppercase:
        disk = c + ':\\'
        if os.path.isdir(disk):
            disk_list.append(disk)

    for path in disk_list:

        if os.path.exists(path):
            thread_t.append(threading.Thread(target=monitor_files, args=[path, ], daemon=True))

    for thr in thread_t:
        thr.start()


def show_noti(path, name):
    window = tk.Tk()
    window.title('河众反病毒软件')
    window.attributes("-topmost", True)

    # 获取屏幕的宽度和高度
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()

    # 计算弹窗的宽度和高度
    window_width = min(screen_width, 500)
    window_height = min(screen_height, 400)

    # 计算弹窗的 x 和 y 坐标，使其显示在右下角
    window_x = screen_width - window_width
    window_y = screen_height - window_height

    # 设置弹窗的尺寸和位置
    window.geometry(f"{window_width}x{window_height}+{window_x}+{window_y}")

    tk.Label(window, text='河众反病毒软件--警告', font=('宋体', 20), width=400, height=1, anchor='center',
             fg='red').pack()
    tk.Label(window, text=f'病毒发现：{name}', font=('微软雅黑', 12), width=400, height=2, wraplength=460, anchor='w',
             fg='red').pack()

    tk.Label(window, text=f'在：{path}', font=('微软雅黑', 16), width=400, height=6, wraplength=470, anchor='w',
             fg='red').pack()

    def close_window():
        window.destroy()

    def countdown(button, window, ti):
        if ti > 0:
            button.config(text=f'我知道了（{ti}秒）')
            window.after(1000, countdown, button, window, ti - 1)
        else:
            button.config(text=f'我知道了')
            window.destroy()

    button = tk.Button(window, text="我知道了（5秒）", command=close_window, width=50, height=3)
    button.pack()
    ti = 5
    countdown(button, window, ti)

    window.mainloop()


def show_noti2(name):
    window = tk.Tk()
    window.title('河众反病毒软件')
    window.attributes("-topmost", True)

    # 获取屏幕的宽度和高度
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()

    # 计算弹窗的宽度和高度
    window_width = min(screen_width, 500)
    window_height = min(screen_height, 300)

    # 计算弹窗的 x 和 y 坐标，使其显示在右下角
    window_x = screen_width - window_width
    window_y = screen_height - window_height

    # 设置弹窗的尺寸和位置
    window.geometry(f"{window_width}x{window_height}+{window_x}+{window_y}")

    tk.Label(window, text='河众反病毒软件--提示', font=('宋体', 20), width=400, height=1, anchor='center',
             fg='red').pack()
    tk.Label(window, text=f'{name}', font=('宋体', 16), width=400, height=5, wraplength=460, anchor='w',
             fg='red').pack()

    def close_window():
        window.destroy()

    def countdown(button, window, ti):
        if ti > 0:
            button.config(text=f'我知道了（{ti}秒）')
            window.after(1000, countdown, button, window, ti - 1)
        else:
            button.config(text=f'我知道了')
            window.destroy()

    button = tk.Button(window, text="我知道了（5秒）", command=close_window, width=50, height=3)
    button.pack()
    ti = 5
    countdown(button, window, ti)

    window.mainloop()


class Watch_FileMonitor(FileSystemEventHandler):
    def __init__(self):
        sc = VirusScan()
        self.yaar = sc.getrules('./bd/yara')
        with open('bd/white.data') as f:
            self.whitedb = f.read()
        self.seter = ConfigParser()
        self.seter.read('cfg.ini')
        self.model = load_model('./bd/hzml.h5')

    def on_created(self, event):  # 利用watchdog监控文件
        global ProtectB
        global md5_watchdatabase
        sc = VirusScan()
        if not event.is_directory:
            try:
                if str(event.src_path).replace('\\', '/').endswith(('.yar', '.log')):
                    pass
                else:
                    threading.Thread(target=proess_watcher_scaner,
                                     args=[self.seter, self.whitedb, self.yaar, sc, self.model, None,
                                           str(event.src_path).replace('\\', '/'),
                                           True]).start()

            except:
                pass

    def on_modified(self, event):  # 利用watchdog监控文件
        global ProtectB
        global md5_watchdatabase
        sc = VirusScan()
        if not event.is_directory:
            try:
                if str(event.src_path).replace('\\', '/').endswith(('.yar', '.log')):
                    pass
                else:
                    threading.Thread(target=proess_watcher_scaner,
                                     args=[self.seter, self.whitedb, self.yaar, sc, self.model, None,
                                           str(event.src_path).replace('\\', '/'),
                                           True]).start()

            except:
                pass

    def show_popup(self, file_path, virus_name):
        for _ in range(1, 2):

            i = 0
            while True:
                i += 1
                filename = str(i) + ".tro"
                filepath = os.path.join('./Malwaregl', filename).replace('\\', '/')
                if not os.path.exists(filepath):
                    lastf = filepath
                    break
            with open(file_path, 'rb') as f:
                fb = f.read()

            fb = base64.b64encode(fb)
            filenumber = os.path.basename(lastf)
            with open('{}'.format(lastf), 'wb') as f:
                f.write(fb)

            with open('./Malwaregl/{}.ini'.format(filenumber), 'w', encoding='utf-8') as f:
                f.write(file_path)
            os.remove(file_path)


def mbrwatcher():
    global watchmbra
    try:
        with open('\\\\.\\PhysicalDrive0', 'rb') as mbrf:
            mbrs = mbrf.read(1024)
        while True:
            time.sleep(0.01)
            with open('\\\\.\\PhysicalDrive0', 'rb') as mbrf:
                mbrs2 = mbrf.read(1024)
            if mbrs2 != mbrs:
                print('发现引导扇区被修改！')
                threading.Thread(target=show_noti2,
                                 args=['监控已经发现您的计算机磁盘保留扇区已经被更改，我们已经修复您的磁盘保留扇区。', ],
                                 daemon=True).start()
                with open('\\\\.\\PhysicalDrive0', 'r+b') as mbrf:
                    mbrf.seek(0)
                    mbrf.write(mbrs)
            if not watchmbra:
                print('退出MBR保护')
                break

    except PermissionError:
        print('权限不足')


def reg_mot2():
    global watchreg
    while watchreg:
        time.sleep(0.1)
        try:
            kye2 = win32api.RegOpenKeyEx(win32con.HKEY_CURRENT_USER,
                                         'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts',
                                         0, win32con.KEY_ALL_ACCESS)
            win32api.RegSetValue(kye2, '.exe', win32con.REG_SZ, '')
            win32api.RegCloseKey(kye2)
            kye1 = win32api.RegOpenKeyEx(win32con.HKEY_CURRENT_USER, 'SOFTWARE\Classes\.exe', 0,
                                         win32con.KEY_ALL_ACCESS)
            if win32api.RegQueryValueEx(kye1, '')[0] != 'exefile':
                win32api.RegSetValue(kye1, '', win32con.REG_SZ, 'exefile')
                print('他奶奶的！')
                threading.Thread(target=show_noti2,
                                 args=[
                                     '发现系统关键注册表被修改：EXE关联项目。注册表已经被修复。', ],
                                 daemon=True).start()
            win32api.RegCloseKey(kye1)
        except:
            pass


def reg_mot():  # reg_mot() 的注册表规则来自PYAS 云酱天天被撅
    global watchreg
    threading.Thread(target=reg_mot2, daemon=True).start()
    while watchreg:
        print(watchreg)
        time.sleep(0.1)
        try:

            regs1 = ["NoControlPanel", "NoDrives", "NoFileMenu", "NoFind", "NoRealMode", "NoRecentDocsMenu",
                     "NoSetFolders",
                     "NoSetFolderOptions", "NoViewOnDrive", "NoClose", "NoRun", "NoDesktop", "NoLogOff",
                     "NoFolderOptions", "RestrictRun", "DisableCMD",
                     "NoViewContexMenu", "HideClock", "NoStartMenuMorePrograms", "NoStartMenuMyGames",
                     "NoStartMenuMyMusic" "NoStartMenuNetworkPlaces",
                     "NoStartMenuPinnedList", "NoActiveDesktop", "NoSetActiveDesktop", "NoActiveDesktopChanges",
                     "NoChangeStartMenu", "ClearRecentDocsOnExit",
                     "NoFavoritesMenu", "NoRecentDocsHistory", "NoSetTaskbar", "NoSMHelp", "NoTrayContextMenu",
                     "NoViewContextMenu", "NoWindowsUpdate",
                     "NoWinKeys", "StartMenuLogOff", "NoSimpleNetlDList", "NoLowDiskSpaceChecks",
                     "DisableLockWorkstation", "NoManageMyComputerVerb",
                     "DisableTaskMgr", "DisableRegistryTools", "DisableChangePassword", "Wallpaper", "NoComponents",
                     "NoAddingComponents", "Restrict_Run"]
            regs2 = [
                win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,
                                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                                    0, win32con.KEY_ALL_ACCESS),
                win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,
                                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                                    0, win32con.KEY_ALL_ACCESS),
                win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,
                                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", 0,
                                    win32con.KEY_ALL_ACCESS),
                win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,
                                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                                    0, win32con.KEY_ALL_ACCESS),
                win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE,
                                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop", 0,
                                    win32con.KEY_ALL_ACCESS),
                win32api.RegOpenKey(win32con.HKEY_CURRENT_USER, r"SOFTWARE\Policies\Microsoft\Windows\System", 0,
                                    win32con.KEY_ALL_ACCESS),
                win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\System", 0,
                                    win32con.KEY_ALL_ACCESS),
                win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,
                                    r"Software\Policies\Microsoft\MMC\{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}", 0,
                                    win32con.KEY_ALL_ACCESS)]
            for rgs2 in regs2:
                for rgs1 in regs1:
                    try:
                        win32api.RegDeleteValue(rgs2, rgs1)
                        threading.Thread(target=show_noti2,
                                         args=[
                                             f'发现系统关键注册表被修改：{str(rgs1)}。注册表已经被修复。', ],
                                         daemon=True).start()

                    except:
                        pass
                win32api.RegCloseKey(rgs2)
        except:
            print('ERROR WATCHREG')


global set_ui


def setyq():
    global setwindow
    global setfrom
    global set_ui

    def onheur():
        global set_ui
        global watcher_dl
        readini = ConfigParser()
        readini.read('cfg.ini', encoding='utf-8')
        readini.set('scan', 'heur', 'True')
        set_ui.label_6.setText('深度学习引擎：开启')
        readini.write(open('cfg.ini', 'r+'))
        watcher_dl = True

    def offheur():
        global set_ui
        global watcher_dl
        readini = ConfigParser()
        readini.read('cfg.ini', encoding='utf-8')
        readini.set('scan', 'heur', 'False')
        set_ui.label_6.setText('深度学习引擎：关闭')
        readini.write(open('cfg.ini', 'r+'))
        watcher_dl = False

    def onyara():
        global set_ui
        readini = ConfigParser()
        readini.read('cfg.ini', encoding='utf-8')
        readini.set('scan', 'yara', 'True')
        set_ui.label_7.setText('Yara规则引擎：开启')
        readini.write(open('cfg.ini', 'r+'))

    def offyara():
        global set_ui
        readini = ConfigParser()
        readini.read('cfg.ini', encoding='utf-8')
        readini.set('scan', 'yara', 'False')
        set_ui.label_7.setText('Yara规则引擎：关闭')
        readini.write(open('cfg.ini', 'r+'))

    def onregprotect():
        pass

    def offregprotect():
        pass

    def onfileprotect():
        global set_ui
        readini = ConfigParser()
        readini.read('cfg.ini', encoding='utf-8')
        readini.set('setting', 'watchfile', 'True')
        set_ui.label_2.setText('实时监控：开启')
        readini.write(open('cfg.ini', 'r+'))
        global ProtectF
        ProtectF = True
        SysWatchTread = threading.Thread(target=runwatcher, daemon=True)
        SysWatchTread.start()

    def offfileprotect():
        global set_ui
        readini = ConfigParser()
        readini.read('cfg.ini', encoding='utf-8')
        readini.set('setting', 'watchfile', 'False')
        set_ui.label_2.setText('实时监控：关闭')
        readini.write(open('cfg.ini', 'r+'))
        global ProtectF
        ProtectF = False

    def onproessp():
        global set_ui
        global prosswa
        readini = ConfigParser()
        readini.read('cfg.ini', encoding='utf-8')
        readini.set('setting', 'watchpross', 'True')
        set_ui.label_4.setText('进程监控：开启')
        readini.write(open('cfg.ini', 'r+'))
        threading.Thread(target=proess_watcher, daemon=True).start()
        prosswa = True

    def offproessp():
        global prosswa
        global set_ui
        readini = ConfigParser()
        readini.read('cfg.ini', encoding='utf-8')
        readini.set('setting', 'watchpross', 'False')
        set_ui.label_4.setText('进程监控：关闭')
        readini.write(open('cfg.ini', 'r+'))
        prosswa = False

    def onmbr():
        global set_ui
        global watchmbra
        readini = ConfigParser()
        readini.read('cfg.ini', encoding='utf-8')
        readini.set('setting', 'watchmbr', 'True')
        set_ui.label_8.setText('引导监控：开启')
        readini.write(open('cfg.ini', 'r+'))
        threading.Thread(target=mbrwatcher, daemon=True).start()
        watchmbra = True

    def offmbr():
        global watchmbra
        global set_ui
        readini = ConfigParser()
        readini.read('cfg.ini', encoding='utf-8')
        readini.set('setting', 'watchmbr', 'False')
        set_ui.label_8.setText('引导监控：关闭')
        readini.write(open('cfg.ini', 'r+'))
        watchmbra = False

    def onscan_skip_big_file():
        global set_ui
        global scan_skip_big_file
        readini = ConfigParser()
        readini.read('cfg.ini', encoding='utf-8')
        readini.set('scan', 'big', 'True')
        set_ui.label_11.setText('扫描跳过大文件：开启')
        readini.write(open('cfg.ini', 'r+'))
        scan_skip_big_file = True

    def offscan_skip_big_file():
        global scan_skip_big_file
        global set_ui
        readini = ConfigParser()
        readini.read('cfg.ini', encoding='utf-8')
        readini.set('setting', 'big', 'False')
        set_ui.label_11.setText('扫描跳过大文件：关闭')
        readini.write(open('cfg.ini', 'r+'))
        scan_skip_big_file = False

    def onregw():
        global set_ui
        global watchreg
        readini = ConfigParser()
        readini.read('cfg.ini', encoding='utf-8')
        readini.set('setting', 'watchreg', 'True')
        set_ui.label_9.setText('注册表监控：开启')
        readini.write(open('cfg.ini', 'r+'))
        watchreg = True
        threading.Thread(target=reg_mot, daemon=True).start()

    def offregw():
        global watchreg
        global set_ui
        readini = ConfigParser()
        readini.read('cfg.ini', encoding='utf-8')
        readini.set('setting', 'watchreg', 'False')
        set_ui.label_9.setText('注册表监控：关闭')
        readini.write(open('cfg.ini', 'r+'))
        watchreg = False

    def onpe():
        global set_ui
        readini = ConfigParser()
        readini.read('cfg.ini', encoding='utf-8')
        readini.set('scan', 'pe', 'True')
        set_ui.label_13.setText('PE启发式引擎：开启')
        readini.write(open('cfg.ini', 'r+'))

    def offpe():
        global set_ui
        readini = ConfigParser()
        readini.read('cfg.ini', encoding='utf-8')
        readini.set('scan', 'pe', 'False')
        set_ui.label_13.setText('PE启发式引擎：关闭')
        readini.write(open('cfg.ini', 'r+'))

    def onc():
        global set_ui
        readini = ConfigParser()
        readini.read('cfg.ini', encoding='utf-8')
        readini.set('scan', 'cloud', 'True')
        set_ui.label_12.setText('云端扫描引擎：开启')
        readini.write(open('cfg.ini', 'r+'))

    def offc():
        global set_ui
        readini = ConfigParser()
        readini.read('cfg.ini', encoding='utf-8')
        readini.set('scan', 'cloud', 'False')
        set_ui.label_12.setText('云端扫描引擎：关闭')
        readini.write(open('cfg.ini', 'r+'))

    def tw_down():
        global set_ui
        readini = ConfigParser()
        readini.read('cfg.ini', encoding='utf-8')
        readini.set('scan', 'updateweb', 'https://down2.hezhongkj.top')
        set_ui.label_15.setText('设置镜像源：河众台湾源')
        readini.write(open('cfg.ini', 'r+'))

    def gz_down():
        global set_ui
        readini = ConfigParser()
        readini.read('cfg.ini', encoding='utf-8')
        readini.set('scan', 'updateweb', 'https://bbs.hezhongkj.top')
        set_ui.label_15.setText('设置镜像源：河众大陆源')
        readini.write(open('cfg.ini', 'r+'))

    def offdlw():
        global set_ui
        readini = ConfigParser()
        readini.read('cfg.ini', encoding='utf-8')
        readini.set('setting', 'dlw', 'False')
        set_ui.label_19.setText('深度学习参与监控：关闭')
        readini.write(open('cfg.ini', 'r+'))

    def ondlw():
        global set_ui
        readini = ConfigParser()
        readini.read('cfg.ini', encoding='utf-8')
        readini.set('setting', 'dlw', 'True')
        set_ui.label_19.setText('深度学习参与监控：开启')
        readini.write(open('cfg.ini', 'r+'))

    def closeEvent8(event):
        event.ignore()
        setwindow.hide()

    readini = ConfigParser()
    readini.read('cfg.ini', encoding='utf-8')
    enheur = readini['scan']['heur']
    enyara = readini['scan']['yara']
    enfile = readini['setting']['watchfile']
    enpros = readini['setting']['watchpross']
    enmbrs = readini['setting']['watchmbr']
    enskip = readini['scan']['big']
    enregw = readini['setting']['watchreg']
    enpe = readini['scan']['pe']
    enc = readini['scan']['cloud']
    update_webs = readini['scan']['updateweb']
    dlws = readini['setting']['dlw']
    setwindow = qtw.QWidget()
    set_ui = setfrom()
    set_ui.setupUi(setwindow)
    setwindow.closeEvent = closeEvent8
    setwindow.setWindowTitle('Hezhong AntiVirus Set')
    setwindow.setWindowIcon(QIcon('r.ico'))
    setwindow.show()
    set_ui.pushButton_7.clicked.connect(onheur)
    set_ui.pushButton_8.clicked.connect(offheur)
    set_ui.pushButton_9.clicked.connect(onyara)
    set_ui.pushButton_10.clicked.connect(offyara)
    set_ui.pushButton.clicked.connect(onfileprotect)
    set_ui.pushButton_2.clicked.connect(offfileprotect)
    set_ui.pushButton_3.clicked.connect(onproessp)
    set_ui.pushButton_5.clicked.connect(offproessp)
    set_ui.pushButton_11.clicked.connect(onmbr)
    set_ui.pushButton_12.clicked.connect(offmbr)
    set_ui.pushButton_13.clicked.connect(onscan_skip_big_file)
    set_ui.pushButton_14.clicked.connect(offscan_skip_big_file)
    set_ui.pushButton_15.clicked.connect(onregw)
    set_ui.pushButton_16.clicked.connect(offregw)
    set_ui.pushButton_20.clicked.connect(onpe)
    set_ui.pushButton_19.clicked.connect(offpe)
    set_ui.pushButton_17.clicked.connect(onc)
    set_ui.pushButton_18.clicked.connect(offc)
    set_ui.pushButton_21.clicked.connect(gz_down)
    set_ui.pushButton_22.clicked.connect(tw_down)
    set_ui.pushButton_23.clicked.connect(ondlw)
    set_ui.pushButton_24.clicked.connect(offdlw)
    setwindow.setFixedSize(setwindow.width(), setwindow.height())
    if enheur == 'True':
        set_ui.label_6.setText('深度学习引擎：开启')
    else:
        set_ui.label_6.setText('深度学习引擎：关闭')
    if enyara == 'True':
        set_ui.label_7.setText('Yara规则引擎：开启')
    else:
        set_ui.label_7.setText('Yara规则引擎：关闭')
    if enfile == 'True':
        set_ui.label_2.setText('实时监控：开启')
    else:
        set_ui.label_2.setText('实时监控：关闭')
    if enpros == 'True':
        set_ui.label_4.setText('进程监控：开启')
    else:
        set_ui.label_4.setText('进程监控：关闭')
    if enmbrs == 'True':
        set_ui.label_8.setText('引导监控：开启')
    else:
        set_ui.label_8.setText('引导监控：关闭')
    if enskip == 'True':
        set_ui.label_11.setText('扫描跳过大文件：开启')
    else:
        set_ui.label_11.setText('扫描跳过大文件：关闭')
    if enregw == 'True':
        set_ui.label_9.setText('注册表监控：开启')
    else:
        set_ui.label_9.setText('注册表监控：关闭')
    if enc == 'True':
        set_ui.label_12.setText('云端扫描引擎：开启')
    else:
        set_ui.label_12.setText('云端扫描引擎：关闭')
    if enpe == 'True':
        set_ui.label_13.setText('PE启发式引擎：开启')
    else:
        set_ui.label_13.setText('PE启发式引擎：关闭')
    if update_webs == 'https://down2.hezhongkj.top':
        set_ui.label_15.setText('设置镜像源：河众台湾源')
    elif update_webs == 'https://bbs.hezhongkj.top':
        set_ui.label_15.setText('设置镜像源：河众大陆源')
    else:
        set_ui.label_15.setText('设置镜像源：其他源 ⚠')
    if dlws == 'True':
        set_ui.label_19.setText('深度学习参与监控：开启')
    else:
        set_ui.label_19.setText('深度学习参与监控：关闭')


clickerconnect = False


class guiscan:
    def __init__(self):
        self.infectedfileslist = None
        self.count_files = None
        self.stopscan = None
        self.directory = None
        self.run = None
        self.infectedfiles = 0
        self.count_files = None
        self.okscans = False
        self.scansfile = 0
        self.fileing = ''
        self.scanlog = ''
        self.gelilist = []
        self.thread_scan_model = None
        self.thread_scan_md5db = ''
        self.thread_scan_yardb = None
        self.thread_scan_fin = False
        self.thread_scan_virname = ''
        self.flists = []
        self.thread_class_scan_1 = None

    def getfilepathgui(self):
        self.directory = qtw.QFileDialog.getExistingDirectory(None, "选择文件夹", '')
        scan_ui.label.setText(self.directory)

    def setrun(self):
        self.run = True

    def setstop(self):
        self.stopscan = True


    def find_lastfile(self, folder):
        last_writable_file = None
        i = 0
        while True:
            i += 1
            filename = str(i) + ".tro"
            filepath = os.path.join(folder, filename)
            if not os.path.exists(filepath):
                last_writable_file = filepath
                break
        return last_writable_file

    def geli(self):
        self.gelilist = []
        global scan_ui
        count = scan_ui.listWidget.count()  # 得到QListWidget的总个数
        print(count)
        glwidght_list = [scan_ui.listWidget.itemWidget(scan_ui.listWidget.item(i))
                         for i in range(count)]
        g = 0
        for cb in glwidght_list:
            if cb.isChecked():
                self.gelilist.append(self.infectedfileslist[g])
                # self.gelilist.append(cb.text().split(']')[0])
            g += 1
        print(self.gelilist)

        for gelifile in self.gelilist:
            try:
                scan_ui.label_4.setText('处理中：{}'.format(gelifile))
                QCoreApplication.processEvents()
                print('加密文件：{}'.format(gelifile))

                with open(gelifile, 'rb') as f:
                    filebytes = f.read()
                fb = base64.b64encode(filebytes)
                lastf = self.find_lastfile('./Malwaregl')
                with open('{}'.format(lastf), 'wb') as f:
                    f.write(fb)
                filenumber = os.path.basename(lastf)
                with open('{}'.format(lastf), 'wb') as f:
                    f.write(fb)
                with open('./Malwaregl/{}.ini'.format(filenumber), 'w', encoding='utf-8') as f:
                    f.write(gelifile)
                print('删除病毒文件！')
                os.remove(gelifile)
                self.infectedfiles -= 1
                QCoreApplication.processEvents()
            except:
                pass
        scan_ui.label_4.setText('所有风险已经处理完成！')

    def govirusscan(self, autostart=False, stpath=None):  # 扫描病毒
        global clickerconnect
        self.run = False
        global scan_ui
        global scanwindow
        global cancelscan
        global scan_skip_big_file

        scan_ui.label_4.setText('还没有扫描')

        if scanwindow.isVisible():
            print('pass')
            pass
        else:
            scan_ui.listWidget.setHorizontalScrollBarPolicy(PyQt5.QtCore.Qt.ScrollBarAlwaysOn)
            scan_ui.listWidget.setHorizontalScrollMode(qtw.QAbstractItemView.ScrollPerPixel)
            scan_ui.listWidget.setSizeAdjustPolicy(qtw.QListWidget.AdjustToContents)
            scanwindow.show()
            if not clickerconnect:
                scan_ui.pushButton.clicked.connect(self.getfilepathgui)
                clickerconnect = True  # 设置标志为True，表示已经连接过了

        def scan_a_file(file, model, md5db, yardb, Avscanclass, useyara, useheur, whitedb, usec, usepe):
            try:
                with open(file, 'rb') as f:
                    fda = f.read()

                self.scanlog += '\n 扫描文件：{}    ......'.format(file)

                md5virus = VirusScan.md5_scan(Avscanclass, file, md5db, fda)
                heurmd5name = md5virus[1]
                if heurmd5name in whitedb:
                    self.thread_scan_fin = True
                    return 0
                QCoreApplication.processEvents()

                # scan_ui.label_6.setText('已经扫描：{}'.format(scansfile))
                if md5virus[0]:
                    print('MD5')
                    self.infectedfiles += 1
                    self.scanlog += '-> 发现了：Malware.Gen'
                    self.thread_scan_fin = True
                    self.thread_scan_virname = 'Malware.Gen'
                    return 0
                if usec == 'True':
                    clor = VirusScan.cscan(Avscanclass, heurmd5name)
                    if clor:
                        self.infectedfiles += 1
                        self.scanlog += '-> 发现了：Malware.Gen(qc)'
                        self.thread_scan_virname = 'Malware.Gen(qc)'
                        self.thread_scan_fin = True
                        return 0




                if useyara == 'True' or useyara is True:  # Yara检查未知病毒
                    yaa = VirusScan.yarascan(Avscanclass, yardb, file, fda)
                    print(yaa)
                    if yaa is None:
                        pass
                    else:
                        print(str(yaa[0]))
                        yaa22 = virusnamedecode(str(yaa[0]))
                        print(yaa22)
                        self.infectedfiles += 1
                        scan_ui.label_5.setText('发现病毒：{}'.format(self.infectedfiles))
                        self.scanlog += '-> 发现了：{}'.format(yaa22)
                        QCoreApplication.processEvents()
                        self.thread_scan_virname = yaa22
                        self.thread_scan_fin = True
                        return 0
                if usepe == 'True':
                    try:
                        peob = pefile.PE(file)
                        if VirusScan.pescan(Avscanclass, hz_funcs, peob):
                            self.infectedfiles += 1

                            self.scanlog += '-> 发现了：HEUR:Trojan.Generic'
                            self.thread_scan_virname = 'HEUR:Trojan.Generic'
                            self.thread_scan_fin = True
                            return 0
                    except:
                        pass
                if useheur == 'True':
                    print('fff')
                    try:
                        pefile.PE(file)
                    except Exception:
                        self.thread_scan_virname = None
                        self.thread_scan_fin = True
                        return 0

                    else:
                        # flist = numpy.array([file])
                        # print(flist)
                        flabels = numpy.zeros((1,))
                        pred = VirusScan.predict(Avscanclass, model, file, flabels, fda, 1, 0)

                        print(pred[0])
                        try:
                            if float(pred[0][0]) >= 0.9:
                                ml_virusname = 'DL.Trojan.{}.a'.format(round(float(pred[0][0]) * 100))
                            elif float(pred[0][0]) >= 0.8:
                                ml_virusname = 'DL.Trojan.{}.b'.format(round(float(pred[0][0]) * 100))
                            elif float(pred[0][0]) >= 0.7:
                                ml_virusname = 'DL.Trojan.{}.c'.format(round(float(pred[0][0]) * 100))
                            else:
                                ml_virusname = None
                        except IndexError:
                            ml_virusname = None
                        if ml_virusname is not None:
                            self.scanlog += '-> 发现了：{}'.format(ml_virusname)
                            self.infectedfiles += 1
                            self.thread_scan_fin = True
                            self.thread_scan_virname = ml_virusname
                            return 0
                        else:
                            self.thread_scan_fin = True
                            return 0
                self.thread_scan_fin = True
                return 0
            except:
                self.thread_scan_virname = None
                self.thread_scan_fin = True
                return 0

        # 修改pushButton_2按钮的处理部分

        def start_scan(stpaths=''):
            global scan_ui
            global scanwindow
            print(stpaths)
            if stpaths == '' or stpaths == False:
                pass
            else:
                print('似乎启动了右键扫描！')
                self.directory = stpaths
                scan_ui.label.setText(self.directory)
            print(self.directory)
            if not self.directory:
                return 0
            self.scanlog = ''
            with open('bd/ver.dll') as f:
                databaseversion = f.read()
            with open('bd/ve.dll') as f:
                softwareversion = f.read()
            with open('bd/bd.vdb') as f:
                md5_database = f.read()
            with open('bd/bd.vdb') as f:
                knoviruses = len(f.readlines())
            with open('bd/white.data') as f:
                whitedb = f.read()

            starttimes = time.time()
            _atimes_ = time.localtime()
            atimes = '{}.{}.{}-{}.{}.{}'.format(_atimes_.tm_year, _atimes_.tm_mon, _atimes_.tm_mday
                                                , _atimes_.tm_hour, _atimes_.tm_min, _atimes_.tm_sec)
            self.scanlog += '''
------------------------HEZHONG ANTIVIRUS SCAN LOG------------------------
开始于:  {}
病毒库版本:  {}
软件版本:  {}
引擎版本:  6.27.1100
记录病毒数量:  {}
------------------------HEZHONG ANTIVIRUS SCAN LOG------------------------
            
            '''.format(atimes, databaseversion, softwareversion, knoviruses)
            scansfile = 0
            self.infectedfiles = 0
            self.stopscan = False
            _list_return = []
            scan_ui.pushButton_3.clicked.connect(self.setstop)
            scan_ui.listWidget.clear()
            self.infectedfileslist = []
            QCoreApplication.processEvents()
            scan_ui.label_5.setText('发现病毒：')
            QCoreApplication.processEvents()
            scan_ui.label_5.setText('发现病毒：')
            QCoreApplication.processEvents()
            scan_ui.label_4.setText('初始化......')
            QCoreApplication.processEvents()
            QCoreApplication.processEvents()

            conf = ConfigParser()
            conf.read('cfg.ini', encoding='utf-8')
            Avscanclass = VirusScan()
            yararule_co = VirusScan.getrules(Avscanclass, './bd/yara')
            useyara = conf['scan']['yara']
            useheur = conf['scan']['heur']
            usepe = conf['scan']['pe']
            usec = conf['scan']['cloud']
            print(useheur)
            scan_skip_big_file = conf['scan']['big']
            model = load_model('./bd/hzml.h5')
            print(yararule_co)


            def scaners(fileer):


                for root, _, files in os.walk(fileer):

                    for file in files:
                        self.thread_scan_fin = False
                        self.thread_scan_virname = ''
                        file = os.path.join(root, file)

                        QCoreApplication.processEvents()
                        if scan_skip_big_file == 'True':
                            if os.path.getsize(file) >= 262144000:
                                continue

                        if 1:
                            # def scan_a_file(file, model, md5db, yardb, Avscanclass, useyara, useheur):
                            self.scansfile += 1
                            # scan_a_file(file, model, md5_database, yararule_co, Avscanclass, useyara,
                            #            useheur, whitedb, usec, usepe)
                            self.thread_class_scan_1 = threading.Thread(target=scan_a_file, args=[file, model, md5_database, yararule_co, Avscanclass, useyara,
                                        useheur, whitedb, usec, usepe])
                            self.thread_class_scan_1.start()
                            while True:
                                if self.thread_scan_fin == True:
                                    break
                                QCoreApplication.processEvents()


                            scan_ui.label_5.setText(f'发现病毒：{self.infectedfiles}')
                            scan_ui.label_6.setText(f'已经扫描：{self.scansfile}')
                            scan_ui.label_4.setText(f'扫描中:{file}')
                            if self.thread_scan_virname == '' or self.thread_scan_virname is None:
                                pass
                            elif self.stopscan:
                                return 0
                            else:
                                self.infectedfileslist.append(file)
                                checkbox = qtw.QCheckBox('[{1}] {0}'.format(file, self.thread_scan_virname))
                                checkbox.setChecked(True)
                                checkbox.setSizePolicy(qtw.QSizePolicy.Expanding, qtw.QSizePolicy.Expanding)
                                checkitem = qtw.QListWidgetItem()
                                sizehint = checkbox.sizeHint()
                                sizehint.setWidth(sizehint.width() * 2)
                                checkitem.setSizeHint(sizehint)
                                scan_ui.listWidget.addItem(checkitem)
                                scan_ui.listWidget.setItemWidget(checkitem, checkbox)
                                QCoreApplication.processEvents()

            try:
                scaners(self.directory)
            except Exception as fe:
                pass

            self.scanlog += f'\n扫描已经完成。耗时{round(time.time() - starttimes, 2)}秒钟，扫描{self.scansfile}文件，扫描{self.infectedfiles}个检测。'
            self.scaansf = None
            self.scansfile = 0
            scan_ui.label_4.setText('扫描完成')
            QCoreApplication.processEvents()
            with open('./logfile/{}.log'.format(atimes), 'w+', encoding='utf-8') as f:
                f.write(self.scanlog)
            gc.collect()
            scan_ui.pushButton_4.clicked.connect(self.geli)


        scan_ui.pushButton_2.clicked.connect(start_scan)
        print(autostart)
        if autostart:
            start_scan(stpath)


def update2check():
    cg = ConfigParser()
    cg.read('cfg.ini')
    down_URL = cg['scan']['updateweb']
    global upui
    global upwin
    if upwin.isVisible():
        pass
    else:
        upwin.show()
    app = wx.App(False)
    with open('./bd/ver.dll', 'rt') as f:
        ve = f.read()
    latve = requests.get(f'{down_URL}/down/ver.txt', verify=False).text

    if latve == ve:
        wx.MessageDialog(None, f'你已经更新到最新版本了！', '更新', wx.YES_NO | wx.ICON_WARNING).ShowModal()
        upwin.hide()
        return 0
    dlg = wx.MessageDialog(None, f'发现病毒数据库可以更新！是否更新？', '更新', wx.YES_NO | wx.ICON_WARNING)
    resu = dlg.ShowModal() == wx.ID_YES
    dlg.Destroy()
    if resu:
        try:
            intver = int(ve)
            intlatver = int(latve)
            chaj = intlatver - intver
            print(chaj)
            for i_i in range(chaj):
                resp1 = requests.get(f'{down_URL}/down/vdbs/{i_i + 1 + intver}.vdb', stream=True,
                                     verify=False)
                print(resp1.headers)
                total1 = int(resp1.headers.get('content-length', 0))
                ci1 = 0
                upui.label_3.setText(f'{down_URL}/down/vdbs/{i_i + 1 + intver}.vdb')
                with open('bd/bd.vdb', 'ab') as f:
                    for chunk1 in resp1.iter_content(chunk_size=1024):
                        if chunk1:  # 过滤掉保持连接的空白chunk
                            ci1 += len(chunk1)
                            f.write(chunk1)
                            # 更新进度条和下载大小显示（进度条将会是不确定的）
                            upui.progressBar.setRange(0, 0)  # 或者使用其他方法来表示不确定的进度
                            upui.label_4.setText('{}KB 已下载'.format(round(ci1 / 1024, 2)))
                            QCoreApplication.processEvents()
        except:
            resp1 = requests.get(f'{down_URL}/down/bd.vdb', stream=True, verify=False)
            print(resp1.headers)
            total1 = int(resp1.headers.get('content-length', 0))
            ci1 = 0
            upui.label_3.setText(f'下载文件：{down_URL}/down/bd.vdb')
            with open('bd/bd.vdb', 'wb') as f:
                for chunk1 in resp1.iter_content(chunk_size=1024):
                    if chunk1:  # 过滤掉保持连接的空白chunk
                        ci1 += len(chunk1)
                        f.write(chunk1)
                        # 更新进度条和下载大小显示（进度条将会是不确定的）
                        upui.progressBar.setRange(0, 0)  # 或者使用其他方法来表示不确定的进度
                        upui.label_4.setText('{}KB 已下载'.format(round(ci1 / 1024, 2)))
                        QCoreApplication.processEvents()

        resp2 = requests.get(f'{down_URL}/down/ver.txt', stream=True, verify=False)
        total2 = int(resp2.headers.get('content-length', 0))
        ci2 = 0
        upui.label_3.setText(f'下载文件：{down_URL}/down/ver.txt')
        with open('bd/ver.dll', 'wb') as f:
            for chunk2 in resp2.iter_content(chunk_size=1024):
                if chunk2:  # 过滤掉保持连接的空白chunk
                    ci1 += len(chunk2)
                    f.write(chunk2)
                    # 更新进度条和下载大小显示（进度条将会是不确定的）
                    upui.progressBar.setRange(0, 0)  # 或者使用其他方法来表示不确定的进度
                    upui.label_4.setText('{}KB 已下载'.format(round(ci2 / 1024, 2)))
                    QCoreApplication.processEvents()
        resp3 = requests.get(f'{down_URL}/down/data1.vdb', stream=True, verify=False)
        total3 = int(resp3.headers.get('content-length', 0))
        ci3 = 0
        upui.label_3.setText(f'下载文件：{down_URL}/down/data1.vdb')
        with open('bd/white.data', 'wb') as f:
            for chunk3 in resp3.iter_content(chunk_size=1):
                if chunk3:  # 过滤掉保持连接的空白chunk
                    ci3 += len(chunk3)
                    f.write(chunk3)
                    # 更新进度条和下载大小显示（进度条将会是不确定的）
                    upui.progressBar.setRange(0, 0)  # 或者使用其他方法来表示不确定的进度
                    upui.label_4.setText('{}KB 已下载'.format(round(ci3 / 1024, 2)))
                    QCoreApplication.processEvents()
        resp4 = requests.get(f'{down_URL}/down/malware.yar', stream=True, verify=False)
        total4 = int(resp3.headers.get('content-length', 0))
        ci4 = 0
        upui.label_3.setText(f'下载文件：{down_URL}/down/malware.yar')
        with open('bd/yara/malware.yar', 'wb') as f:
            for chunk4 in resp4.iter_content(chunk_size=1024):
                if chunk4:  # 过滤掉保持连接的空白chunk
                    ci4 += len(chunk4)
                    f.write(chunk4)
                    # 更新进度条和下载大小显示（进度条将会是不确定的）
                    upui.progressBar.setRange(0, 0)  # 或者使用其他方法来表示不确定的进度
                    upui.label_4.setText('{}KB 已下载'.format(round(ci4 / 1024, 2)))
                    QCoreApplication.processEvents()

        # re1 = requests.get('https://bbs.hezhongkj.top/down/bd.fne', verify=False).text
        # re2 = requests.get('https://bbs.hezhongkj.top/down/ver.txt', verify=False).text
        # re3 = requests.get('https://bbs.hezhongkj.top/down/data1.vdb', verify=False).text
        # re4 = requests.get('https://bbs.hezhongkj.top/down/malware.yar', verify=False).text

    dl = wx.MessageDialog(None, f'更新完成！', '更新',
                          wx.YES_DEFAULT | wx.ICON_QUESTION)

    upwin.hide()
    resu_ = dl.ShowModal() == wx.ID_YES
    dl.Destroy()
    app.MainLoop()  # 启动wxPython的主事件循环


def update1check():
    if upwin.isVisible():
        pass
    else:
        upwin.show()
    vet = requests.get('https://bbs.hezhongkj.top/down/ve.dll', verify=False).text
    with open('bd/ve.dll', 'r') as f:
        ve = f.read()

    if ve != vet:
        app = wx.App(False)  # 创建一个wxPython的App实例

        dlg = wx.MessageDialog(None, f'发现软件主程序可以更新！是否更新？',
                               '更新', wx.YES_NO | wx.ICON_WARNING)
        result = dlg.ShowModal() == wx.ID_YES
        dlg.Destroy()
        app.MainLoop()  # 启动wxPython的主事件循环
        if result:
            wx.MessageDialog(None, f'更新过程中软件会无响应，请耐心等待下载文件', '更新',
                             wx.YES_DEFAULT | wx.ICON_QUESTION)
        else:
            return 0
        resp9 = requests.get('https://bbs.hezhongkj.top/down/Setup.exe', stream=True, verify=False)
        print(resp9.headers)
        ci9 = 0
        upui.label_3.setText('下载文件：https://bbs.hezhongkj.top/down/Setup.exe')
        with open('Setup.exe', 'wb') as f:
            for chunk9 in resp9.iter_content(chunk_size=1024):
                if chunk9:  # 过滤掉保持连接的空白chunk
                    ci9 += len(chunk9)
                    f.write(chunk9)
                    # 更新进度条和下载大小显示（进度条将会是不确定的）
                    upui.progressBar.setRange(0, 0)  # 或者使用其他方法来表示不确定的进度
                    upui.label_4.setText('{}KB 已下载'.format(round(ci9 / 1024, 2)))
                    QCoreApplication.processEvents()

        wx.MessageDialog(None, f'更新需要关闭软件以及所有防护', '更新',
                         wx.YES_DEFAULT | wx.ICON_QUESTION).ShowModal()
        os.popen('start Setup.exe')
        sys.exit()
    else:
        update2check()


global innmu2___, innmu2__, innmu2_


def geliqu():
    global glui
    global glwin
    all = os.listdir('./Malwaregl')
    allf = []
    glwin.show()
    glui.textBrowser.setText('')
    glui.textBrowser.append('注意：出现{}*{}是因为一些软件已知问题，请无视！')

    for i in all:
        try:
            allf.append(i.split('.')[0])
        except Exception:
            pass
    print(allf)
    allf___ = allf

    for i in allf___:
        try:
            with open(f'./Malwaregl/{i}.tro.ini', encoding='utf-8') as f:
                recpath = f.read()
            glui.textBrowser.append(f'文件编号：{i}，源目录：{recpath}')
            QCoreApplication.processEvents()
        except:
            pass

    def hf():
        print('C')
        if 1:
            countinput = glui.lineEdit.text()
            print('')
            if '-' in countinput:
                count1 = countinput.split('-')[0]
                count2 = countinput.split('-')[1]
                for ii in range(int(count1), int(count2) + 1):
                    with open(f'./Malwaregl/{ii}.tro') as f:
                        encryptsfile = f.read()
                    with open(f'./Malwaregl/{ii}.tro.ini', encoding='utf-8') as f:
                        filenumber = f.read()
                    decofile = base64.b64decode(encryptsfile)
                    with open(filenumber, 'wb') as f:
                        f.write(decofile)
                    os.remove(f'./Malwaregl/{ii}.tro')
                    os.remove(f'./Malwaregl/{ii}.tro.ini')
                    glui.label.setText(f'恢复：{filenumber}')
                    glui.textBrowser.setText('')
                    QCoreApplication.processEvents()
                    for i in all:
                        try:
                            if i == 'files':
                                continue
                            allf.append(i.split('.')[0])

                        except Exception:
                            pass
                    print(allf)
                    allf___ = allf

                    for i in allf___:
                        try:
                            with open(f'./Malwaregl/{i}.tro.ini', encoding='utf-8') as f:
                                recpath = f.read()
                            glui.textBrowser.append(f'文件编号：{i}，源目录：{recpath}')
                            QCoreApplication.processEvents()
                        except:
                            pass
            else:
                with open(f'./Malwaregl/{countinput}.tro') as f:
                    encryptsfile = f.read()
                with open(f'./Malwaregl/{countinput}.tro.ini', encoding='utf-8') as f:
                    filenumber = f.read()
                decofile = base64.b64decode(encryptsfile)
                with open(filenumber, 'wb') as f:
                    f.write(decofile)
                os.remove(f'./Malwaregl/{countinput}.tro')
                os.remove(f'./Malwaregl/{countinput}.tro.ini')
                glui.label.setText(f'恢复：{filenumber}')
                glui.textBrowser.setText('')
                QCoreApplication.processEvents()
                for i in all:
                    try:
                        if i == 'files':
                            continue
                        allf.append(i.split('.')[0])

                    except Exception:
                        pass
                print(allf)
                allf___ = allf

                for i in allf___:
                    try:
                        with open(f'./Malwaregl/{i}.tro.ini', encoding='utf-8') as f:
                            recpath = f.read()
                        glui.textBrowser.append(f'文件编号：{i}，源目录：{recpath}')
                        QCoreApplication.processEvents()
                    except:
                        pass

    glui.pushButton.clicked.connect(hf)


def about():
    global abwin
    if abwin.isVisible():
        print('pass')
        pass
    else:
        abwin.show()


class UpdateProtectText_1(PyQt5.QtCore.QThread):
    uptext_single = PyQt5.QtCore.pyqtSignal(list)

    def __init__(self):
        super(UpdateProtectText_1, self).__init__()

    def run(self):
        global mainui
        conf = ConfigParser()

        while True:
            time.sleep(0.1)
            conf.read('cfg.ini')
            pt1 = conf['setting']['watchpross']
            pt2 = conf['setting']['watchfile']
            pt3 = conf['setting']['watchmbr']
            pt4 = conf['setting']['watchreg']
            self.uptext_single.emit([pt1, pt2, pt3, pt4])


class UpdateProtectText_m(object):
    def update(self, msg):
        global mainui
        pt1 = msg[0]
        pt2 = msg[1]
        pt3 = msg[2]
        pt4 = msg[3]
        try:
            if pt2 == 'True':
                if mainui is not None and mainui.label_3 is not None:
                    mainui.label_3.setText('文件监控：开启')
            else:
                if mainui is not None and mainui.label_3 is not None:
                    mainui.label_3.setText('文件监控：关闭')

            if pt1 == 'True':
                if mainui is not None and mainui.label_4 is not None:
                    mainui.label_4.setText('进程监控：开启')
            else:
                if mainui is not None and mainui.label_4 is not None:
                    mainui.label_4.setText('进程监控：关闭')

            if pt3 == 'True':
                if mainui is not None and mainui.label_5 is not None:
                    mainui.label_5.setText('引导监控：开启')
            else:
                if mainui is not None and mainui.label_5 is not None:
                    mainui.label_5.setText('引导监控：关闭')
            if pt4 == 'True':
                if mainui is not None and mainui.label_7 is not None:
                    mainui.label_7.setText('注册表监控：开启')
            else:
                if mainui is not None and mainui.label_7 is not None:
                    mainui.label_7.setText('注册表监控：关闭')
            if pt1 != 'True' or pt2 != 'True' or pt3 != 'True' or pt4 != 'True':
                pixm = PyQt5.QtGui.QPixmap('./UI/lib/prot2.png')
                mainui.label_2.setPixmap(pixm)
                mainui.label_6.setText('设备可能未受保护')
                mainui.label_6.setStyleSheet("color:orange")
            else:
                pixm = PyQt5.QtGui.QPixmap('./UI/lib/prot1.png')
                mainui.label_2.setPixmap(pixm)
                mainui.label_6.setText('设备已经受到保护')
                mainui.label_6.setStyleSheet("color:green")

        except Exception as fe:
            pass


def maingui():
    global mainui
    global scan_ui
    global scanwindow
    global glui
    global glwin
    global MainWindow
    global app11
    global upui
    global upwin
    global abwin
    global uptext_single

    def cfbutton1():
        print('按钮触发1')
        # 显示已创建的ScanWindow实例
        try:
            # 显示已创建的ScanWindow实例
            _a = guiscan()
            _a.govirusscan()
        except Exception as e:
            print("异常:", e)

    def cfbutton2():
        print('按钮触发2')

        try:

            setyq()
        except Exception as e:
            print("异常:", e)

    def cfbutton3():
        print('按钮触发3')

        try:
            geliqu()
        except:
            pass

    def cfbutton4():
        print('按钮触发4')

        try:

            about()
        except Exception as e:
            print("异常:", e)

    def closeEvent(event):
        event.ignore()
        MainWindow.hide()

    def closeEvent2(event):
        event.ignore()
        scanwindow.hide()

    def closeEvent3(event):
        event.ignore()
        glwin.hide()

    def closeEvent4(event):
        event.ignore()
        upwin.hide()

    def closeEvent5(event):
        event.ignore()
        abwin.hide()

    app11 = qtw.QApplication(sys.argv)
    MainWindow = qtw.QMainWindow()
    mainui = lobbywindow()
    mainui.setupUi(MainWindow)
    MainWindow.closeEvent = closeEvent  # 重写closeEvent方法

    scanwindow = qtw.QWidget()
    scan_ui = scanform()
    scan_ui.setupUi(scanwindow)
    scanwindow.closeEvent = closeEvent2
    glwin = qtw.QWidget()
    glui = glfrom()
    glui.setupUi(glwin)
    glwin.closeEvent = closeEvent3
    upwin = qtw.QWidget()
    upui = updatefrom()
    upui.setupUi(upwin)
    upwin.closeEvent = closeEvent4
    abwin = qtw.QWidget()
    abui = abofrom()
    abui.setupUi(abwin)
    abwin.closeEvent = closeEvent5

    mainui.hub_chasha.clicked.connect(cfbutton1)
    mainui.hub_setting.clicked.connect(cfbutton2)
    mainui.hub_setting_4.clicked.connect(cfbutton3)
    mainui.hub_setting_2.clicked.connect(update1check)
    mainui.hub_setting_5.clicked.connect(cfbutton4)
    MainWindow.setWindowTitle('Hezhong AntiVirus Main')
    MainWindow.setWindowIcon(QIcon('r.ico'))
    scanwindow.setWindowTitle('Hezhong AntiVirus Scaner')
    scanwindow.setWindowIcon(QIcon('r.ico'))
    glwin.setWindowTitle('Hezhong AntiVirus Quarantine')
    glwin.setWindowIcon(QIcon('r.ico'))
    upwin.setWindowTitle('Hezhong AntiVirus Online Update')
    upwin.setWindowIcon(QIcon('r.ico'))
    MainWindow.setFixedSize(MainWindow.width(), MainWindow.height())
    glwin.setFixedSize(glwin.width(), glwin.height())
    scanwindow.setFixedSize(scanwindow.width(), scanwindow.height())
    abwin.setFixedSize(abwin.width(), abwin.height())
    upwin.setFixedSize(upwin.width(), upwin.height())
    MainWindow.show()
    updatelobbytext_1 = UpdateProtectText_1()
    updatelobbytext = UpdateProtectText_m()
    updatelobbytext_1.start()
    updatelobbytext_1.uptext_single.connect(updatelobbytext.update)
    sys.exit(app11.exec_())


def except_hook(cls, exception, traceback):
    sys.__excepthook__(cls, exception, traceback)

parser = argparse.ArgumentParser()
parser.add_argument('-sf', '--scanfile', type=str, default='')
args = parser.parse_args()

if __name__ == "__main__":
    os.chdir(os.path.abspath(os.path.dirname(__file__)))

    global scan_ui
    global scanwindow
    sys.excepthook = except_hook
    global prosswa
    global ProtectF
    global app11
    QtCore.QCoreApplication.setAttribute(QtCore.Qt.AA_EnableHighDpiScaling)
    PyQt5.QtGui.QGuiApplication.setAttribute(QtCore.Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    conf = ConfigParser()
    conf.read('cfg.ini')

    pt1 = conf['setting']['watchpross']
    pt2 = conf['setting']['watchfile']
    pt3 = conf['setting']['watchreg']
    heur = conf['scan']['heur']
    yar = conf['scan']['yara']
    if args.scanfile != '':
        l_scan_path = args.scanfile
        try:
            if os.path.isdir(l_scan_path):
                # 显示已创建的ScanWindow实例
                app11 = qtw.QApplication(sys.argv)


                scanwindow = qtw.QWidget()
                scan_ui = scanform()
                scan_ui.setupUi(scanwindow)
                scanwindow.setWindowTitle('Hezhong AntiVirus Scaner')
                scanwindow.setWindowIcon(QIcon('r.ico'))
                _a__a = guiscan()
                _a__a.govirusscan(autostart=True, stpath=l_scan_path)
                sys.exit(app11.exec_())
            else:
                exit()
        except Exception as e:
            print("异常:", e)
    else:
        cg = ConfigParser()
        cg.read('cfg.ini')
        if cg['setting']['watchfile'] == 'True':
            ProtectF = True
            threading.Thread(target=runwatcher, daemon=True).start()
        if cg['setting']['watchpross'] == 'True':
            threading.Thread(target=proess_watcher, daemon=True).start()
            prosswa = True
        if cg['setting']['watchmbr'] == 'True':
            print('r')
            threading.Thread(target=mbrwatcher, daemon=True).start()
            watchmbra = True
        if cg['setting']['watchreg'] == 'True':
            print('r')
            watchreg = True
            threading.Thread(target=reg_mot, daemon=True).start()

        softwaretp()
        maingui()
