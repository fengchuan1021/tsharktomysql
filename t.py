import requests

session=requests.session()
ret=session.post('http://192.168.1.36:8080/query',json={'file_path':'2.pcap','index':'1000000'}).json()
print(ret['data'])
#
# ret=session.post('http://192.168.1.36:8080/insert',json={'file_path':'1.pcap','tablename':'fengchuantttttttt'})
# print(ret.content)