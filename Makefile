
PYTHON=python3

all: inits build_proc rminits


build_proc:
	make -C wayround_org/gsasl all
	$(PYTHON) ./setup.py build_ext --inplace

clean: rminits clean2

clean2:
	make -C wayround_org/gsasl clean


inits:
	# workaround for cython pep-420 incompatability
	touch wayround_org/__init__.py

rminits:
	# removing workaround for cython pep-420 incompatability
	-rm wayround_org/__init__.py
