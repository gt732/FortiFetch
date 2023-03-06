FROM python:3.9-slim-buster

COPY fortifetch /usr/src/app/fortifetch

WORKDIR /usr/src/app/fortifetch

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "/usr/src/app/fortifetch/db/db.py"]