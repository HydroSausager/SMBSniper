# SMBSniper
## Что это
Удобная тулза для упрощения перечисления содержимого SMB шар, хранящая данные в локальной sqlite БД и выводом результатов в xlsx таблицу для последующего анализа.

## Как юзать
```
usage: python3 ./smbsniper.py target (or targetfile.txt) -u user@domain [-p password] [-t threads count]

Handy SMB script

positional arguments:
  target                [[domain/]username[:password]@]<target address or IP range or IP list file>

options:
  -h, --help            show this help message and exit
  -t THREADS, --threads THREADS
                        Threads count
  -d DEPTH, --depth DEPTH
                        Depth of crawling
  -e EXCLUDED-SHARES, --exclude EXCLUDED-SHARES
                        Shares excluded from share crawling separated by comma
  -x XLSX-FILENAME, --xlsx XLSX-FILENAME
                        Full results xlsx filename
  -H NTLM-HASH, --hash NTLM-HASH
                        NTLM Hash
  --timeout TIMEOUT     timeout for connections
```

## Примеры:
### Пройтись по IP/FQDN из тестового файла
```
python3 ./smbsniper.py consoso.com/admin:qweqwe123@targets.txt
```
### Пройтись по подсети с запросом пароля
```
python3 ./smbsniper.py consoso.com/admin@192.168.0/24
python3 ./smbsniper.py consoso.com/admin@192.168.0.0-255
python3 ./smbsniper.py consoso.com/admin@192.168.0.0-192.168.0.255
```
### Null сессия в 4 потока исключая кравлинг шар 'print$'
```
python3 ./smbsniper.py 192.168.0.0/24 -t 4 -e 'print$'
```
