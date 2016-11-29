
PYTHON=python3

all: inits build_proc rminits


build_proc:
	make -C wayround_i2p/gsasl all
	$(PYTHON) ./setup.py build_ext --inplace

clean: rminits clean2

clean2:
	make -C wayround_i2p/gsasl clean


inits:
	# workaround for cython pep-420 incompatability
	touch wayround_i2p/__init__.py

rminits:
	# removing workaround for cython pep-420 incompatability
	-rm wayround_i2p/__init__.py
