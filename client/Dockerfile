# Use the official lightweight Python image.
FROM python:3.12-slim

# Allow statements and log messages to immediately appear in the logs
ENV PYTHONUNBUFFERED True

# Copy local code to the container image
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .

ENV PORT=8501
CMD streamlit run ./app.py --server.port=${PORT} --server.address=0.0.0.0
