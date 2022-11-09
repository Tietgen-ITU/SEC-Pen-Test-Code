.PHONY: gen-certs run

gen-certs:
	./scripts/gen_certs.sh

run:
	python3 app.py
