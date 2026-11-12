FROM python:3.12-slim-bookworm

# Native libraries Chromium needs
RUN apt-get update && apt-get install -y --no-install-recommends \
    libatomic1 \
    libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 \
    libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 libcairo2 \
    libasound2 libatspi2.0-0 libx11-xcb1 libxcursor1 libxi6 \
    libxss1 libxtst6 fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Use python -m to avoid PATH issues — this is the actual fix
RUN python -m playwright install --with-deps chromium

WORKDIR /app
COPY . .

ENV PORT=5555
EXPOSE $PORT

CMD ["sh", "-c", "python app.py --host 0.0.0.0 --port ${PORT} --headless --transport chromium"]
