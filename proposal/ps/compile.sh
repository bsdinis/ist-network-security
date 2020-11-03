#!/usr/bin/env sh
#!/bin/env sh

for f in $(ls *.eps); do epstopdf $f; done
mv *.pdf ../img

