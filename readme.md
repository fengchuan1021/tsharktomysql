## 需要python3环境

###### 安装包

pip install pyshark
pip install fastapi
pip install uvicorn

###### 启动服务

 nohup /home/ubuntu/conda/bin/uvicorn main:app --host 0.0.0.0 --port 8080 >/dev/null 2>&1 &

###### 使用方法

```python
import requests
session=requests.session()
ret=session.post('http://192.168.1.36:8080/query',json={'file_path':'/home/ubuntu/resovepcap/1.pcap','index':'1'})
print(ret.content)
ret=session.post('http://192.168.1.36:8080/insert',json={'file_path':'/home/ubuntu/resovepcap/1.pcap','tablename':'fengchuan'})
print(ret.content)
```

