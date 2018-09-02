# zippkg 0.1

Vision of this project is build a powerful zip read and write tool. 
Python environment: python 2.7

I got some problems when I use Python2.7 standard lib `zipfile`. Here are the reasons why I started this project:

* Bad support for unicode file name
* Not support AES encryption, such as: AES128, AES192, AES256
* Not so good code style
* Not convenience to support other zip features


## ZipReader and ZipWriter

`ZipReader`: reader for zip file. It is supports zip64, zip standard decryption, AES decryption.

`ZipWriter`: writer for zip file. Supports zip standard encryption, AES encryption. 


## TODO
ZipWriter support zip64

## Example

```python
from zippkg import ZipReader, ZipWriter

# example for zipreader
with ZipReader("test.zip") as zipreader:
    for name in zipreader.namelist():
        print name

# example for zipwriter
with ZipWriter("test.zip", password="pwd") as zipwriter:
    zipwriter.writestr("file.txt", "content")
    zipwriter.write("file1.txt")
```


## links

[http://www.winzip.com/win/en/aes_info.htm](http://www.winzip.com/win/en/aes_info.htm)  
[https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)  
[https://opensource.apple.com/source/zip/zip-6/unzip/unzip/proginfo/extra.fld](https://opensource.apple.com/source/zip/zip-6/unzip/unzip/proginfo/extra.fld)
