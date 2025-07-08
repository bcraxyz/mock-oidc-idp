# Use the official lightweight Python image.
FROM python:3.12-slim

# Allow statements and log messages to immediately appear in the logs
ENV PYTHONUNBUFFERED True

# Copy local code to the container image
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .

# Run the web service on container startup.
CMD ["gunicorn", "--bind", "0.0.0.0:$(PORT)", "app:app"]
