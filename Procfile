release: python manage.py migrate
web: gunicorn password_manager.wsgi:application --log-file - --log-level debug
python manage.py collectstatic --noinput