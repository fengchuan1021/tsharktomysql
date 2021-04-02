import requests

session=requests.session()
ret=session.post('http://192.168.1.92:8080/query',json={'file_path':'1.pcap','index':'1'}).json()
print(ret['data'])
#
# # ret=session.post('http://192.168.1.36:8080/insert',json={'file_path':'1.pcap','tablename':'fengchuantttttttt'})
# # print(ret.content)

# import lxml.etree as ET
#
# import subprocess
# def main():
#     t1cmd = f"tshark -r 2.pcap -V -T pdml"
#     t1 = subprocess.Popen(t1cmd, shell=True, stdout=subprocess.PIPE)
#     it = ET.iterparse(t1.stdout, ['start', 'end'])
#     for event, elem in it:
#         # print(event)
#         # print(1111111)
#         # print(elem)
#         elem.clear()
# main()