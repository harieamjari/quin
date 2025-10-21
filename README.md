# Quin
## What's this?

A quinary cipher for SMS encryption.

## How does it work?

By representing the GSM characters in quinary digits (0, 1, 2, 3, 4).

More on this PDF [article](https://texlive2020.latexonline.cc/compile?git=https://github.com/harieamjari/quin&target=quin.tex&command=pdflatex&download=quin.pdf).

## Cool, how can I use it?
### Encryption

```
$ ./quin e Hello\ World 'Some Ve@ryLong Password123' 
 040 430 432 312 133 100 240 422 443 320 314 344 300 303 443 234 442 243 140 342 203 041 204 014 044 111 430 404 402 123 124 030 044 103 133 021 013 441 123 221 304 440 330 204 112  ΛΓE:Ä£Π¡cülä¥NcuJaΩIM-fixÉΓh6VoåxLÄ#P1V%gΣΦf8
```
### Decryption

```
$ ./quin d 'ΛΓE:Ä£Π¡cülä¥NcuJaΩIM-fixÉΓh6VoåxLÄ#P1V%gΣΦf8' 'Some Ve@ryLong Password123'
 242 104 314 314 124 211 223 124 424 314 004 000 000 000 000 000 000 000 000 000 000 000 000 000 000 000 000 000 000 000 000 000 000 000 000 000 000 000 000 000 000 000 000 000 000  Hello World@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
 ```
