PY=.venv/bin/python
all: fetch s01 s02 s03 s04
fetch:
	$(PY) fetch_data.py
s01:
	$(PY) s01_overview.py
s02:
	$(PY) s02_split.py
s03:
	$(PY) s03_figures.py
s04:
	$(PY) s04_methodology.py
.PHONY: all fetch s01 s02 s03 s04
