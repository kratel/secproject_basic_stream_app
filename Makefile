

.PHONY: lint setup_deb_venv

lint:
	flake8 streaming_secured_client.py streaming_secured_server.py

setup_deb_venv:
	pip install -r requirements_ubuntu.txt
