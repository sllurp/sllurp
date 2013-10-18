.PHONY: all install clean tar

all:
	python setup.py build

install:
	python setup.py install

clean:
	rm -rf *~ *.pyc

tar: clean
	python setup.py sdist --formats=gztar

