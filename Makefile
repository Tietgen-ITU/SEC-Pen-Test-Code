.PHONY: gen-certs run prod deps setup

gen-certs:
	./scripts/gen_certs.sh

run:
	python3 app.py

deps:
	pip3 install flask flask-limiter click backports.pbkdf2 gunicorn

setup: deps gen-certs

prod: setup
	gunicorn --certfile certs/cert.pem --keyfile certs/key.pem -b 0.0.0.0:8080 -w 1 'app:create_app()'
