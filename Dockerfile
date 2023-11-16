FROM python:3.9

# Set the working directory to /app
WORKDIR /app

COPY ./send.py /app/

CMD ["python", "send.py"]