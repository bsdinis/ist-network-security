#!/usr/bin/env sh

name=A41_Tue_1700_8_proposal
(cd ps && ./compile.sh )
pdflatex $name.tex
biber $name.bib
pdflatex $name.tex
pdflatex $name.tex
