.PHONY: test validate demo
test:
	python3 scripts/acceptance.py
validate:
	python3 validate.py --patched correct --out artifacts/correct
demo:
	python3 validate.py --patched incomplete --out artifacts/incomplete; test $$? -eq 10
