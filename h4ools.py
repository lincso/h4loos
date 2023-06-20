
from ttkbootstrap import Style
import tkinter as tk
from  tkinter  import ttk
import tkinter.filedialog as tk_fld
import tkinter.messagebox as messagebox
import os
import requests
import json
import jsonpath
import hashlib
import threading

"""
Created:2022-04-12
Description:h4loos
Version:1.2
@author: 1inc50
"""

#初始化窗口
def main_windwo_init():
   window=tk.Tk()
   style=Style(theme='darkly')
   window=style.master
   window.title('h4loos')
   #window.iconbitmap('tos.ico')
   mainmenu=tk.Menu(window)
   fillmenu=tk.Menu(mainmenu,tearoff=False)
   #居中
   width = 600
   height = 400
   screen_width=window.winfo_screenwidth()
   screen_height=window.winfo_screenheight()
   x=int(screen_width / 2 -width / 2)
   y=int(screen_height / 2 -height / 2)
   size='{}x{}+{}+{}'.format(width,height,x,y)
   window.geometry(size)

#ui设计
   fillmenu=tk.Menu(mainmenu,tearoff=False)
   fillmenu.add_command(label='威胁查询',command=switch_to_ip)
   fillmenu.add_separator()
   fillmenu.add_command(label='提交文件',command=switch_to_file)
   mainmenu.add_cascade(label='查询',menu=fillmenu)

   toolsmenu=tk.Menu(mainmenu,tearoff=False)
   toolsmenu.add_command(label="后续~",command=back)
   mainmenu.add_cascade(label="工具",menu=toolsmenu)

   helpmenu=tk.Menu(mainmenu,tearoff=False)
   helpmenu.add_command(label='API_Key',command=switch_to_key)
   helpmenu.add_separator()
   helpmenu.add_command(label='网络测试',command=connect)
   mainmenu.add_cascade(label='帮助',menu=helpmenu)

   window.config(menu=mainmenu)
   return window


#测试网络连通性
def connect():
    exit_code = os.system('curl www.baidu.com')
    if exit_code:
        tk.messagebox.showwarning('h4loos','请正确连接网络后使用...')
    else:
        tk.messagebox.showinfo('h4loos','网络正常')

def filekey():
    filename=os.getcwd()+"\key.txt"
    with open(filename,'r',encoding='utf-8') as f:
        res=f.read()
    return res

def apikey_save():
    frame_input=tk.Frame(main_window)
    tk.Label(frame_input,text='Key:',width=5).grid(row=0,column=0, padx=5, pady=5)
    api_get=tk.StringVar()
    entry_key_start=tk.Entry(frame_input,textvariable=api_get,bg='#DDDDDD',width=40).grid(row=0,column=1,padx=5,pady=5)
    def entry_is_true():
        key_len=len(api_get.get())
        if key_len==0:
            tk.messagebox.showwarning('h4loos','请输入你的apikey')
        else:
            filename=os.getcwd()+"\key.txt"
            #print(filename)
            if not os.path.exists(filename):
                with open(filename,'w',encoding='utf-8') as f:
                    f.write(api_get.get())
                    f.close()
                tk.messagebox.showinfo('h4loos','保存成功')
            else:
                tk.messagebox.showinfo('h4loos','文件已存在，如果需要更改请打开文件手动更改')
    tk.Button(frame_input,text='保存',width=12,command=entry_is_true).grid(row=0,column=2, padx=5, pady=5)
    return frame_input


def back():
    tk.messagebox.showinfo('h4loos',"请等待后续更新ovo")

#初始化界面
def ip_input_init():
    frame_input=tk.Frame(main_window)
    tk.Label(frame_input,text='IP:',width=5).grid(row=0,column=0, padx=5, pady=5)
    ip_get=tk.StringVar()
    entry_ip_start=tk.Entry(frame_input,textvariable=ip_get,bg='#DDDDDD',width=40).grid(row=0,column=1,padx=5,pady=5)
    def ip_search():
        result_value=ip_get.get()
        url="https://api.threatbook.cn/v3/scene/ip_reputation"
        query = {
            "apikey":filekey(),
            "resource":result_value, #114.114.114.114
            "lang":'zh'
    }
        response=requests.request('GET',url,params=query)
        response_value=response.json()
        i=0
        result_ip=tk.Text(frame_input,width=60,height=10)
        result_ip.grid(row=2,column=0,columnspan=5, padx=5, pady=5)     #此处布局不能写成一句话不然会导致将返回值置空报错'NoneType' object has no attribute 'insert'

        #自定义输出  注释ctrl+k ctrl+c |反注释ctrl+k ctrl+u

        #危害程度
        result_ip.insert('insert',"\n威胁级别：")
        sev_value=response_value['data'][result_value]['severity']
        #sev_dic={'critical':'严重','high':'高','medium':'中','low':'低','info':'无危胁'}   根据返回增加字典翻译，后api增加api查询后删除
        result_ip.insert('insert',sev_value)
        
        #可信度
        result_ip.insert('insert',"\n情报可信度：")
        conf_value=response_value['data'][result_value]['confidence_level']
        #conf_dic={'critical':'严重','high':'高','medium':'中','low':'低','info':'无危胁'}
        result_ip.insert('insert',conf_value)

        #情报标签
        result_ip.insert('insert',"\n情报信息：")
        jud_value=response_value['data'][result_value]['judgments']
        # jud_dic={'C2':'远控','Botnet':'僵尸网络','Hijacked':'劫持','Phishing':'钓鱼','Malware':'恶意软件','Exploit':'漏洞利用','Scanner':'扫描','Zombie':'傀儡机','Spam':'垃圾邮件','Suspicious':'可疑','Compromised':'失陷主机','Brute Force':'暴力破解','Proxy':'代理','Info':'基础信息','MiningPool':'矿池','CoinMiner':'私有矿池','Sinkhole C2':'安全机构接管C2',
        #          'Backbone':'骨干网','Whitelist':'白名单','IDC':'IDC服务器','SSH Brute Force':'SSH暴力破解','FTP Brute Force':'FTP暴力破解','SMTP Brute Force':'SMTP暴力破解','Http Brute Force':'HTTP AUTH暴力破解','Web Login Brute Force	':'撞库',
        #          'HTTP Proxy':'HTTP Proxy','HTTP Proxy In':'HTTP代理入口','HTTP Proxy Out':'HTTP代理出口','Socks Proxy':'Socks代理','Socks Proxy In':'Socks代理入口','Socks Proxy Out':'Socks代理出口','VPN':'VPN代理',
        #          'VPN In':'VPN入口','VPN Out':'VPN出口','Tor':'Tor代理','Tor Proxy In':'Tor入口','Tor Proxy Out':'Tor出口','Bogon':'保留地址','FullBogon':'未启用IP','Gateway':'网关','Dynamic IP':'动态IP','Edu':'教育','DDNS':'动态域名','Mobile':'移动基站',
        #          'Search Engine Crawler':'搜索引擎爬虫','Advertisement':'广告','CDN':'CDN服务器','DNS':'DNS服务器','BTtracker':'BT服务器','ICP':'ICP备案'}
        while i<len(jud_value):
            out_jud=jud_value[i]
            result_ip.insert('insert',out_jud+" ")
            i +=1
        
        #更新时间
        result_ip.insert('insert',"\n情报更新时间：")
        update_value=response_value['data'][result_value]['update_time']
        result_ip.insert('insert',update_value)

    #判断输入是否为空
    def entry_is_true():
        ip_len=len(ip_get.get())
        if ip_len==0:
            tk.messagebox.showwarning('h4loos','请输入要查询的IP')
        else:
            ip_search()

    
    tk.Button(frame_input,text='提交',width=12,command=entry_is_true).grid(row=0,column=2, padx=5, pady=5)
    result_ip=tk.Text(frame_input,width=60,height=10).grid(row=2,column=0,columnspan=5, padx=5, pady=5)
    return frame_input

def file_input_init():
    frame_input=tk.Frame(main_window)
    tk.Label(frame_input,text='请选择文件:',width=8).grid(row=0,column=0,padx=5,pady=5)
    var_choose=tk.StringVar()
    entry_file_start=tk.Entry(frame_input,textvariable=var_choose,width=40).grid(row=0,column=1,padx=5,pady=5)
    tk.Button(frame_input,text='查询',command=lambda: set_file(var_choose)).grid(row=0,column=2,padx=5, pady=5)
    #单选按钮
    label_radio=tk.Label(frame_input,text='请选择沙箱:',width=8).grid(row=1,column=0)
    label_radio_type=tk.StringVar()
    for win_type,win_title,num in win_types:
        b=tk.Radiobutton(frame_input,text=win_title,variable=label_radio_type,value=win_type)
        b.grid(row=2,column=num)
    for win2_type,win2_title,num in win2_types:
        b=tk.Radiobutton(frame_input,text=win2_title,variable=label_radio_type,value=win2_type)
        b.grid(row=3,column=num)
    for linux_type,linux_title,num in linux_types:
        b=tk.Radiobutton(frame_input,text=linux_title,variable=label_radio_type,value=linux_type)
        b.grid(row=4,column=num)
    label_radio_type.set('win7_sp1_enx64_office2013')
    
    def file_analysis():
        url='https://api.threatbook.cn/v3/file/report'
        radio_value=label_radio_type.get()
        file_dir=var_choose.get()
        with open(file_dir,'rb')as f:
            sha256obj=hashlib.sha256()
            sha256obj.update(f.read())
            hash_value=sha256obj.hexdigest()
        params = {
            'apikey': filekey(),
            'sandbox_type': radio_value,
            'sha256': hash_value
    }
        response = requests.get(url,params=params)
        response_value=response.json()
        return response_value

    #文件分析
    def file_info():
        fruns=file_analysis()
        #print(fruns)
        result_output=tk.Text(frame_input,width=60,height=10)
        result_output.grid(row=9,column=0,columnspan=2, padx=5, pady=5)

        #文件md5
        result_output.insert('insert',"md5值：")
        md5_value=fruns['data']['summary']['md5']
        if md5_value==0:
            result_output.insert('insert','无')
        else:
            result_output.insert('insert',md5_value)

        #文件类型
        result_output.insert('insert',"\n文件类型：")
        type_value=fruns['data']['summary']['file_type']
        result_output.insert('insert',type_value)

        #反病毒扫描引擎检出率
        result_output.insert('insert',"\n反病毒扫描：")
        eng_value=fruns['data']['summary']['multi_engines']
        result_output.insert('insert',eng_value)

        #威胁等级
        result_output.insert('insert',"\n威胁等级：")
        thr_value=fruns['data']['summary']['threat_level']
        thr_dic={'malicious':'恶意','suspicious':'可疑','clean':'安全'}
        result_output.insert('insert',thr_dic.get(thr_value))

        #威胁等级
        result_output.insert('insert',"\n威胁类型：")
        mal_value=fruns['data']['summary']['malware_type']
        mal_dic={'APT':'APT','Backdoor':'后门','Exploit':'漏洞利用','Keylogger':'键盘记录器','RAT':'远程木马','Rootkit':'Rootkit','Bootkit':'Bootkit','Stealer':'窃密','Trojan':'木马','Worm':'蠕虫','Virus':'病毒',
                 'Ransomware':'勒索软件','Spyware':'间谍软件','Riskware':'风险软件','PWS':'密码窃取者','Malware':'恶意软件','Hacktool':'黑客工具','Adware':'广告软件','Pack':'壳','Rogueware':'流氓软件','Pornware':'色情软件','Tool':'工具',
                 'PUA':'潜在有害应用','PUP':'潜在有害程序','Joke':'恶搞软件','Grayware':'灰色软件','Susware':'可疑软件'}
        result_output.insert('insert',mal_dic.get(mal_value))

    def file_network():
        fruns=file_analysis()
        result_output=tk.Text(frame_input,width=60,height=10)
        result_output.grid(row=9,column=0,columnspan=2, padx=5, pady=5)

        #网络行为
        dom=0
        result_output.insert('insert',"网络行为：")
        result_output.insert('insert',"\n域名：")
        dom_values=jsonpath.jsonpath(fruns,'$.data.network.domains[*].domain')
        if dom_values==0:
            result_output.insert('insert',"无")
        else:
            while dom<len(dom_values):
                result_output.insert('insert',dom_values[dom]+" ")
                dom +=1
        http=0
        result_output.insert('insert',"\nHTTP：")
        http_values=jsonpath.jsonpath(fruns,'$.data.network.http[*].uri')
        if http_values==0:
            result_output.insert('insert',"无")
        else:
            while http<len(http_values):
                result_output.insert('insert',http_values[http]+" ")
                http +=1

        tcp=0
        result_output.insert('insert',"\nTCP：")
        tcp_values=jsonpath.jsonpath(fruns,'$.data.network.tcp[*].dst')
        if tcp_values==0:
            result_output.insert('insert','无')
        else:
            while tcp<len(tcp_values):
                result_output.insert('insert',tcp_values[tcp]+" ")
                tcp +=1
    def file_signature():
        fruns=file_analysis()
        result_output=tk.Text(frame_input,width=60,height=10)
        result_output.grid(row=9,column=0,columnspan=2, padx=5, pady=5)

        #行为描述
        desc=0
        result_output.insert('insert',"行为描述：")
        desc_values=jsonpath.jsonpath(fruns,'$.data.signature[*].description')
        if desc_values==0:
            result_output.insert('insert','无')
        else:
            while desc<len(desc_values):
                result_output.insert('insert',"\n"+desc_values[desc])
                desc +=1
                
     
    #判断输入是否为空
    def entry_is_true():
        choose_len=len(var_choose.get())
        if choose_len==0:
            tk.messagebox.showwarning('h4loos','请选择要分析的样本')
        else:
           if comvalue.get()=='基础信息':
            file_info()
           elif comvalue.get()=='通信网络':
            file_network()
           elif comvalue.get()=='样本行为':
            file_signature()

    tk.Label(frame_input,text='获取:',width=8).grid(row=8,column=0, padx=5, pady=5)
    comvalue=tk.StringVar()
    comboxlist=ttk.Combobox(frame_input,textvariable=comvalue)
    comboxlist['value']=('基础信息','通信网络','样本行为')
    comboxlist.current(0)
    comboxlist.grid(row=8, column=1, padx=5, pady=5)
    btn_get_file_name = tk.Button(frame_input, text='开始分析',command=entry_is_true)
    btn_get_file_name.grid(row=8, column=2, padx=5, pady=5)
    result_output=tk.Text(frame_input,width=60,height=10)
    result_output.grid(row=9,column=0,columnspan=2, padx=5, pady=5)

    return frame_input

#沙箱类型
win_types=[('win7_sp1_enx86_office2007','Office2007',0),('win7_sp1_enx86_office2010','Office2010',1)]
win2_types=[('win7_sp1_enx86_office2013','Office2013',0),('win7_sp1_enx64_office2013','Office2013_x64',1)]
linux_types=[('ubuntu_1704_x64','Ubuntu_x64',0),('centos_7_x64','Centos_x64',1)]



#获取文件路径
def set_file(arg):
    set_path=tk_fld.askopenfilename()
    arg.set(set_path)


def switch_init():
    frame_mode=tk.Frame(main_window)

def switch_to_ip():
    global input_ip
    input_ip.destroy()
    input_file.destroy()
    input_key.destroy()
    input_ip=ip_input_init()
    input_ip.place(x=5,y=10)

def switch_to_file():
    global input_file
    input_ip.destroy()
    input_file.destroy()
    input_key.destroy()
    input_file=file_input_init()
    input_file.place(x=5,y=10)

def switch_to_key():
    global input_key
    input_ip.destroy()
    input_file.destroy()
    input_key.destroy()
    input_key=apikey_save()
    input_key.place(x=5,y=10)

main_window=main_windwo_init() #创建主窗口

input_ip=ip_input_init()
input_file=file_input_init()
input_key=apikey_save()

input_ip.place(x=5,y=10)

switch_init()

main_window.mainloop()
