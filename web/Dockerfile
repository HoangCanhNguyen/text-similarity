FROM python:3
WORKDIR /usr/src/app
COPY requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt
COPY . .
RUN pip3 install ./spacy-2.2.4.tar.gz
CMD ["python","app.py"]