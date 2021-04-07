FROM tiangolo/uvicorn-gunicorn-fastapi:python3.8
RUN sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list && sed -i '{s/\(deb.*security\)/#\1/}' /etc/apt/sources.list
RUN apt-get clean
RUN pip install pymysql
RUN apt update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y tshark
COPY ./app /app