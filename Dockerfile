FROM python:3.13.3-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /code

# Install build tools for bcrypt and cryptography
RUN apt-get update && apt-get install -y \
    build-essential \
    libffi-dev \
    python3-dev \
    libssl-dev \
    cargo \
    && rm -rf /var/lib/apt/lists/*

# Install pipenv and app dependencies
COPY Pipfile Pipfile.lock ./
RUN pip install pipenv && pipenv install --system

# Copy the app code
COPY . .

CMD ["python", "manage.py", "runserver"]
