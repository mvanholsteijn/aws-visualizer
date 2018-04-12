include Makefile.mk
USERNAME=mvanholsteijn
NAME=aws-visualizer

do-build:
	python setup.py check
	python setup.py build

push:
	rm -rf dist/*
	python setup.py sdist
	twine upload dist/*

clean:
	python setup.py clean
	rm -rf build/* dist/*

install:
	python setup.py install
