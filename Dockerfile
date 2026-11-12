FROM python:3.12-slim-bookworm

# System dependencies for Chromium / Playwright
RUN apt-get update && apt-get install -y --no-install-recommends \
    libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 \
    libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 libcairo2 \
    libasound2 libatspi2.0-0 libx11-xcb1 libxcursor1 libxi6 \
    libxss1 libxtst6 fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright's Chromium binary with all remaining deps
RUN playwright install --with-deps chromium

# Copy the app
WORKDIR /app
COPY . .

# Railway provides $PORT automatically
ENV PORT=5555
EXPOSE $PORT

# --host 0.0.0.0 is mandatory; 127.0.0.1 is unreachable from outside the container
CMD ["python", "app.py", "--host", "0.0.0.0", "--port", "$PORT", "--headless", "--transport", "chromium"]
