"""Ponto de entrada WSGI para o gunicorn (servidor de producao).

Uso: gunicorn --preload wsgi:app
Com --preload o banco e inicializado uma unica vez no processo mestre,
antes de os workers serem criados.
"""

from app import app, init_db

with app.app_context():
    init_db()
