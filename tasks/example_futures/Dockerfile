# Use an official lightweight Python image.
# In production, this should be a pinned hash like openclaw/python@sha256:...
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Prevent Python from writing pyc files and buffering stdout
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install dependencies
# We use a multi-stage build or just a single layer for simplicity here
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY data_generator.py .
COPY strategy_pandas.py .
COPY main.py .

# Create a non-root user for security (Best Practice!)
RUN useradd -m worker && chown -R worker /app
USER worker

# Entrypoint
CMD ["python", "main.py"]
