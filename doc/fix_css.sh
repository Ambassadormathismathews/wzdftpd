#!/bin/sh

# TODO check if files were already patched !!

if [ -d $1 ]; then
  cd $1

  for file in *.html; do
    sed -e 's:></HEAD:><link rel="STYLESHEET" href="../../css/design2.css"></HEAD:g' $file > tmp
    sed -e 's:/docbook-dsssl/:../images/:g' tmp > tmp2
    rm tmp
    ../add_header_footer.pl tmp2 > $file
  done
else
  sed -e 's:></HEAD:><link rel="STYLESHEET" href="../../css/design2.css"></HEAD:g' $file > tmp
  sed -e 's:/docbook-dsssl/:../images/:g' tmp > tmp2
  rm tmp
  mv tmp2 $file
  ../add_header_footer.pl tmp2 > $file
fi
