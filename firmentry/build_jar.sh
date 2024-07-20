#!/bin/bash

ROOT=$(cd "$(dirname "$0")"; pwd)

mvn install:install-file \
   -Dfile=$ROOT/analyzer/lib/ghidra.jar \
   -DgroupId=ghidra \
   -DartifactId=ghidra \
   -Dversion=10.2.2 \
   -Dpackaging=jar \
   -DgeneratePom=true

cd $ROOT/analyzer
mvn clean compile package
cp target/analyzer-1.0-SNAPSHOT-jar-with-dependencies.jar ../firmrec-static.jar
cd -
