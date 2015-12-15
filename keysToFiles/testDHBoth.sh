#!/bin/sh
CMD_JAVA="java -classpath /workarea/ibinyami/eclipse_workspace/test/bin/ test.DHKeyAgreement2"
CMD_CRYPTO=./dh-agree-java.exe
$CMD_JAVA generate
$CMD_CRYPTO generate
$CMD_JAVA agree
$CMD_CRYPTO agree
