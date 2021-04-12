## 用途
解析pcap文件，并存入数据库    
分为 1. 开发测试版 和 2. 部署项目版

## 需要python3环境
在不修改pip指向pip3的情况下， 以下的pip 需要使用 pip3

## 1.开发测试，
部署项目可以直接看2

###### 安装包
pip install fastapi    
pip install uvicorn     
sudo apt install tshark    
pip install pymysql

###### 启动服务
通过uvicorn开启服务，main是注入的脚本(作为业务应用逻辑去执行)和 host等是基本配置  
uvicorn main:app --host 0.0.0.0 --port 8080    
(/home/ubuntu/conda/bin/uvicorn main:app --host 0.0.0.0 --port 8080)    

 nohup /home/ubuntu/conda/bin/uvicorn main:app --host 0.0.0.0 --port 8080 >/dev/null 2>&1 &    

###### 使用方法实例
直接执行 python3 t.py    

t.py文件内容如下
```python
import requests
session=requests.session()
#查询
ret=session.post('http://192.168.1.36:8080/query',json={'file_path':'/home/ubuntu/resovepcap/1.pcap','index':'1'})
print(ret.content)
# 解析1.pcap文件，并将解析数据存入对应表中
ret=session.post('http://192.168.1.36:8080/insert',json={'file_path':'/home/ubuntu/resovepcap/1.pcap','tablename':'fengchuan'})
print(ret.content)
```

## 2.部署到服务器

docker build -t resolvepcapimg  .

数据库配置以命令行方式传给docker内程序

docker run -d --name resolvepcapap -p 8080:80 -e host=192.168.1.36 -e user=fengchuan -e password=bOelm#Fb2aX -e database=topo_p2p -e port=3306 -v /data/pcaps:/data/pcaps resolvepcapimg



