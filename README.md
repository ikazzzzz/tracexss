<details>
<summary>Tentang</summary>

TraceXSS merupakan network hacking tools yang digunakan untuk mengirim payload berbahaya yang biasa digunakan untuk melakukan serangan XSS. URL yang merespon payload yang dikirimkan akan terdeteksi sebagai kerentanan XSS.
TraceXSS terintegrasi dengan module Crawl yang berfungsi untuk mendapatkan list URL yang berkaitan dengan suatu domain dari arsip Wayback.

</details>

<details>
<summary>Cara Install</summary>

1. Extract .zip
2. `$ cd tracexss`
3. `$ pip3 install -r requirements`

</details>

<details>
<summary>Cara Penggunaan</summary>

- `$ python3 tracexss.py -d <nama_domain>`
- `$ python3 tracexss.py -d testphp.vulnweb.com`

- `$ python3 tracexss.py -f <nama_file_url.txt>`
- `$ python3 tracexss.py -f urls.txt`

- `$ python3 tracexss.py -u <url>`
- `$ python3 tracexss.py -u http://testphp.vulnweb.com/pp=FUZZ`

- `$ python3 tracexss.py -d <nama_domain> -o <file_output.txt>`
- `$ python3 tracexss.py -d testphp.vulnweb.com -o hasil.txt`

*Apabila ada eror, pakai SUDO

</details>

<details>
<summary>Kontributor</summary>

Team 2 x RKS Trace:
1. Zaki Qorindi (2120101765)
2. Ahmad Anwary Adzirudin (2120101671)
3. Bayu Purwadi (2120101685)

</details>
