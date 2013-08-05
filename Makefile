install:
	python setup.py install

clean: clean_clients
	rm -rf *~ *.pyc

clean_clients:
	$(MAKE) -C clients clean

tar: clean
	python setup.py sdist --formats=gztar

.PHONY: install
.PHONY: clean clean_clients
