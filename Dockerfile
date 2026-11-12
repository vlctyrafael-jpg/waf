FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBIAN_FRONTEND=noninteractive \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    WAF_WARM_PAGES=2 \
    WAF_SESSION_MAX_AGE=120

WORKDIR /app

# System dependencies for Chromium (Playwright's official deps).
# python:3.11-slim has NONE of these — without them Chromium won't start
# and you get exactly "Connection closed while reading from the driver".
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl wget gnupg \
    libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
    libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 \
    libgbm1 libpango-1.0-0 libcairo2 libasound2 libatspi2.0-0 \
    libx11-6 libxcb1 libxext6 libxshmfence1 \
    fonts-liberation fonts-unifont fontconfig \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt \
 && python -m playwright install --with-deps chromium

COPY . .

ENV PORT=5555 HOST=0.0.0.0
EXPOSE 5555

CMD ["sh", "-c", "python app.py --host 0.0.0.0 --port ${PORT}"]
