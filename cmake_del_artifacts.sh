#!/bin/sh

cd src || exit
./cmake_del_artifacts.sh
cd ..

cd doc || exit
./cmake_del_artifacts.sh
cd ..

rm -rf \
	build \
	CMakeCache.txt \
	CMakeFiles \
	CPackConfig.cmake \
	CPackSourceConfig.cmake \
	CMakeFiles \
	cmake_install.cmake \
	CTestTestfile.cmake \
	DartConfiguration.tcl \
	install_manifest.txt \
	Testing \
	Makefile

