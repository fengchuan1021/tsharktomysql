import requests

session=requests.session()
ret=session.post('http://192.168.1.36:8080/query',json={'file_path':'1.pcap','index':'3'}).json()
print(ret['data'])

# ret=session.post('http://192.168.1.92:8081/insert',json={'file_path':'/home/ubuntu/resovepcap/1.pcap','tablename':'fengchuan'})
# print(ret.content)