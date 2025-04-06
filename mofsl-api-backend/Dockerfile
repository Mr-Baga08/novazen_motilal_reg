# backend/Dockerfile

FROM python:3.11

# Set workdir
WORKDIR /app

# Copy requirements
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the backend code
COPY . .

# Expose the Flask port
EXPOSE 5005

# Run the app
CMD ["python", "app.py"]
