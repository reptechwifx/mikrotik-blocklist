FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py ./app.py
COPY html ./html
COPY conf-dist ./conf-dist
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

ENV BLOCKLIST_CONF_DIR=/app/conf

EXPOSE 8000

ENTRYPOINT ["/entrypoint.sh"]
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
