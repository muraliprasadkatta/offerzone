#!/bin/sh
set -e

echo "Installing dependencies..."
pip install -r requirements.txt

echo "Running migrations..."
python manage.py migrate --noinput

echo "Starting gunicorn..."
gunicorn offerzone.wsgi:application --bind 0.0.0.0:$PORT
