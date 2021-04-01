import sys
import pymysql
import subprocess
import time



def getlayer_level(packet):
    for layer in packet.layers[::-1]:
        if layer.layer_name == 'data':
            continue
        elif layer.layer_name in ["tcp" "udp"]:
            return '传输层'
        elif layer.layer_name in ["ip", "icmpv6", "icmpv4", "traceroute"]:
            return "网络层"
        elif layer.layer_name in ['arp', 'eth']:
            return '链路层'

        return "应用层"


def createtable(tablename, host, user, password, database):
    connection = pymysql.connect(host=host,
                                 user=user,
                                 password=password,
                                 database=database, autocommit=True)
    cur = connection.cursor()
    create_table_sql = f'''
        CREATE TABLE if not exists `{tablename}`  (
           `hop` int(11) NOT NULL,
          `layer_level` varchar(16) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
          `id` int(11) NOT NULL,
           `sniff_time` datetime(6) NULL DEFAULT NULL,
           `length` int(11) NULL DEFAULT NULL,
          `srcip` varchar(40) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
          `dstip` varchar(40) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,

          `proto_name` varchar(16) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
          `ttl` int(11) NOT NULL,
          `version` int(11) NOT NULL,
          `srcmac` varchar(18) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
          `dstmac` varchar(18) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,



          PRIMARY KEY (`id`) USING BTREE,
          INDEX `ip`(`srcip`) USING BTREE,
          INDEX `proto`(`proto_name`) USING BTREE,
          INDEX `hop`(`hop`) USING BTREE
        ) ENGINE = InnoDB AUTO_INCREMENT = 1 CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Dynamic;
    '''
    cur.execute(create_table_sql)
    cur.close()
    connection.close()


def run_mysql(tablename, host, user, password, database):
    mysql_cmd = f'mysql -u {user} -p{password} {database} -h {host} -e "LOAD DATA LOCAL INFILE \'/dev/stdin\' ignore INTO TABLE {tablename} FIELDS TERMINATED BY \'\\t\' lines terminated by \'\\n\';"'
    print(mysql_cmd)
    mysqlprocess = subprocess.Popen(mysql_cmd, shell=True, stdin=subprocess.PIPE)
    return mysqlprocess


def run_tshark(filename, mysqlprocess):
    tshark_cmd = f"tshark -r {filename} -E occurrence=f -E separator=/t -t ad -T fields -e frame.number -e _ws.col.Time -e frame.len -e ip.src -e ip.dst -e _ws.col.Protocol -e ip.ttl -e ip.version -e eth.src -e eth.dst"
    print(tshark_cmd)
    tsharkprocess = subprocess.Popen(tshark_cmd, shell=True, stdout=subprocess.PIPE)
    while 1:
        buf = tsharkprocess.stdout.readline()
        if not buf:
            break
        try:
            arr = buf.split(b'\t')
            print(arr)
            hop = 1
            #arr[1] = str(datetime.datetime.fromtimestamp(float(arr[1])).strftime("%Y-%m-%d %H:%m:%S")).encode()

            if not arr[3]:
                arr[3]=b'\\N'
            if arr[6]:
                ttl = int(arr[6])
                if ttl <= 32:
                    hop = 33 - ttl
                elif ttl <= 64:
                    hop = 65 - ttl
                elif ttl <= 128:
                    hop = 129 - ttl
                elif ttl <= 255:
                    hop = 256 - ttl
            s = b'\t'.join([str(hop).encode(), b''] + arr)
            mysqlprocess.stdin.write(s)
        except Exception as e:
            print(e)
            print(arr)


def insert_function(filename,tablename):

    host = "192.168.1.36"
    user = "fengchuan"
    password = "bOelm#Fb2aX"
    database = "topo_p2p"
    createtable(tablename, host, user, password, database)
    mysqlprocess = run_mysql(tablename, host, user, password, database)
    run_tshark(filename, mysqlprocess)
    mysqlprocess.stdin.close()
    while mysqlprocess.poll() is None:
        time.sleep(0.2)

from pydantic import BaseModel
from fastapi import FastAPI
class Arg(BaseModel):
    file_path: str
    tablename: str

app = FastAPI()
@app.post('/insert')
def insert(arg:Arg):
    insert_function(arg.file_path,arg.tablename)
    return {'status': 200, 'msg':'ok'}

class Qarg(BaseModel):
    file_path: str
    index: int

def query_function(filepath,index):
    cmd=f'tshark -r {filepath} -Y "frame.number=={index}" -V -T text'
    tsharkprocess = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,encoding='utf-8')
    out,error=tsharkprocess.communicate()
    arr=[]
    dic={}
    s=''
    for line in out.splitlines():
        if not line.strip():
            continue
        if not line.startswith('    '):
            if s:
                dic['children']={'title':s}
                arr.append(dic)
                s=''
                dic={}
            dic['title']=line
        else:
            s+=line+"\n"
    dic['children']={'title':s}
    arr.append(dic)
    retarr={'status':200,'data':arr}
    return retarr
@app.post('/query')
def query(arg:Qarg):
    return query_function(arg.file_path,arg.index)



