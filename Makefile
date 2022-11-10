.PHONY: gen-certs dev prod deps setup staging

# Setup related targets
gen-certs:
	./scripts/gen_certs.sh

deps:
	pip3 install flask flask-limiter click backports.pbkdf2 gunicorn

setup: deps gen-certs

# Targets for running the system in specific environments/modes
dev: 
	python3 app.py 8022

staging:
	gunicorn --certfile certs/cert.pem --keyfile certs/key.pem -b 0.0.0.0:8022 -w 1 'app:create_app()'

prod:
	gunicorn --certfile certs/cert.pem --keyfile certs/key.pem -b 0.0.0.0:443 -w 1 'app:create_app()'

