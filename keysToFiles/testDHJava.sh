#!/bin/sh
CMD="java -classpath /workarea/ibinyami/eclipse_workspace/test/bin/ test.DHKeyAgreement2"
TYPE_A=Java
TYPE_B=Crypto
$CMD generate
mv /tmp/$TYPE_A.priv /tmp/$TYPE_B.priv
mv /tmp/$TYPE_A.pub /tmp/$TYPE_B.pub
$CMD generate
$CMD agree
mv /tmp/$TYPE_A.priv /tmp/$TYPE_B.priv2
mv /tmp/$TYPE_A.pub /tmp/$TYPE_B.pub2
mv /tmp/$TYPE_B.priv /tmp/$TYPE_A.priv
mv /tmp/$TYPE_B.pub /tmp/$TYPE_A.pub
mv /tmp/$TYPE_B.priv2 /tmp/$TYPE_B.priv
mv /tmp/$TYPE_B.pub2 /tmp/$TYPE_B.pub
$CMD agree
