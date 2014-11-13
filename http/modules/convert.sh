#!/bin/bash

for filename in * ; do
    [ -f "$filename" ] || continue
    iconv -f GBK -t UTF-8 "$filename" -o "$filename"
done

