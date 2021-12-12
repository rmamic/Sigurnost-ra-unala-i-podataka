# Izvještaji iz laboratorijskih vježbi

# 1. Laboratorijska vježba

12.10.20211.

## Man-in-the-middle attacks (ARP spoofing)

Realizirati man in the middle napad iskorištavanjem ranjivosti ARP protokola. Student će testirati napad u virtualiziranoj Docker mreži (Docker container networking) koju čine 3 virtualizirana Docker računala (eng. container): dvije žrtve station-1 i station-2 te napadač evil-station.

U ovoj vježbi koristili smo **Windows** terminal te u istoj smo otvorili **Ubuntu** terminal na wsl sustavu.

### Alati koje smo koristili:

**Kloniranje repozitorija**

$ git clone [https://github.com/mcagalj/SRP-2021-22](https://github.com/mcagalj/SRP-2021-22)

**Promjena direktorija**

$ cd SRP-2021-22/arp-spoofing/

**Pokretanje virtualiziranog mrežnog scenarija(Docker)**

$ chmod +X ./start.sh
$ ./start.sh

**Zaustavljanje virtualiziranog mrežnog scenarija**

$ chmod +X ./stop.sh
$ ./stop.sh

**Ispis s dockera**

$ docker ps

uname

hostname

**Ispisivanje mrežne konfiguracije**

$ ifconfig -a

**Ulaz u station**

$ docker exec -it station-1 bash

**Provjera komunikacije između dva stationa**

$ ping station-2

**Otvaranje servera TCP na portu 9000 pomoću netcat-a na kontejneru station-1**

$ netcat -lp 9000

**Otvaranje client TCP-a na hostname.u station-1 9000 pomoću netcat-a na kontejneru station-2**

$ netcat station-1 9000

### Arpspoof

![arp_spoofing.png](Izvjes%CC%8Ctaji%20iz%20laboratorijskih%20vjez%CC%8Cbi%206b6048bb52174e48a0125f4105ebc692/arp_spoofing.png)

**Pokretanje napada u evil-station-u**

$ arpspoof -t station-1 station-2

**Pokretanje tcpdump-a u drugom evil-station-u (docker-u) i praćenje prometa** 

$ tcpdump

**Onemogućavanje slanja poruka iz station-1 u station-2**

$ echo 0 < /proc/sys/net/ipv4/ip_forward

### Još alata:

**Čišćenje screen-a** 

//ctrl+L

**Ispis direktrorija**

$ ls -

**Brži ispis komande**

//tab

**Prekid programa**

//ctrl+C

**Razdjela ekrana**

//shift+alt

**HUB** - omogućuje povezivanje više računala u jednu mrežu

**SWITCH** - povezuje različite uređaje zajedno na jednoj računalnoj mreži

# 2. Laboratorijska vježba

26.10.2021.

## Symmetric key cryptography - a crypto challenge

Riješiti odgovarajući crypto izazov, odnosno dešifrirati odgovarajući *ciphertext* u kontekstu simetrične kriptografije. Izazov počiva na činjenici da student nema pristup enkripcijskom ključu.

Za pripremu crypto izazova, odnosno enkripciju korištena je Python biblioteka cryptography. *Plaintext* koji student treba otkriti enkriptiran je korištenjem high-level sustava za simetričnu enkripciju iz navedene biblioteke - Fernet.

Pripremljeni su nam personalizirani izazovi na internom serveru.

**Pokretanje virtual python okruženja**

$ python -m venv srp

$ activate

$ pip install cryptography

$ from cryptography.fernet import Fernet

**Funkcija koja generira ključ koji dekriptira podatke**

$ key = Fernet.generate_key

$ python 

$ f = Fernet(key)

**Primjer korištenja varijabli u pythonu**

$ plaintext = b"hello world"

$ print("helo world")

//b označava byte-e u kojima treba biti enkriptirana riječ

**Enkriptiranje poruke**

$ ciphertext = F.encrypt(b"hello world")

**Dekriptiranje poruke**

$ F.decrypt(ciphertext)

**Izlazak iz pythona**

$ exit()

**Odlazak u VS → kodiranje**

$ code brute_force.py

**U VS Brute-force attack code**

```jsx
#datoteke koje importamo kako bismo ih mogli koristiti

import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes

#hash f-ja za generiranje naziva datoteke koju trebamo dekriptirati (Secure Hash Algortihm 256)

def hash(input):
    if not isinstance(input, bytes):
        input = input.encode()

    digest = hashes.Hash(hashes.SHA256())
    digest.update(input)
    hash = digest.finalize()

    return hash.hex()

#f-ja koja provjerava je li ono što je enkriptirano slika png formata

def test_png(header):
		if header.startswith(b"\211PNG\r\n\032\n"):
		return True

#f-ja u kojoj izvršavamo napad

def brute_force():
		filename = "ime_datoteke.encrypted"

#Reading from a file
		with open(filename, "rb") as file:
		ciphertext = file.read()
#brojač ključeva
		ctr = 0
		while True:
		key_bytes = ctr.to_bytes(32, "big")
		key = base64.urlsafe_b64encode(key_bytes)

#ispis svakog provjerenog 1000tog ključa
		if not(ctr + 1) % 1000:
		printf(f"[*] Keys tested: {ctr + 1:,}", end = "\r")

#izlazak iz infinite loop-a
		try:
		plaintext = Fernet(key).decrypt(ciphertext)
		header = plaintext[:32]

#je li slika?
		if test_png(header):
		printf(g"[+] KEY FOUND: {key}")

#Writing to file ono što smo dekriptirali
		with open("lol.png", "wb") as file:
		file.write(plaintext)

#izlazimo iz while-a jer smo pronašli ključ
		break
		except Exception:
			pass
		ctr += 1
		if __name__=="__main__":
		brute_force()
		#h = hash('mamic_rosana')

#print(h)
```

**Dekriptirana slika**

![WhatsApp Image 2021-10-26 at 12.36.18.jpeg](Izvjes%CC%8Ctaji%20iz%20laboratorijskih%20vjez%CC%8Cbi%206b6048bb52174e48a0125f4105ebc692/WhatsApp_Image_2021-10-26_at_12.36.18.jpeg)

# 3. Laboratorijska vježba

9.11.2021.

## **Message Authentication Code (MAC)**

Implementirali smo zaštitu integriteta sadržaja dane poruke primjenom odgovarajućeg *message authentication code (MAC)* algoritma. Koristili smo HMAC mehanizam iz Python biblioteka cryptography. Radili smo sa simetričnim ključem. MAC algoritam dodaje neki sadržaj na poruku. Poruka ide od pošiljatelja do primatelja i onda se uspoređuje MAC algoritam s primateljevim i ako je različit, integritet je narušen.

**Funkcija za izračun MAC vrijednosti za danu poruku:**

```jsx
from cryptography.hazmat.primitives import hashes, hmac

def generate_MAC(key, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    signature = h.finalize()
    return signature
```

**Funkcija za provjeru validnosti MAC-a za danu poruku:**

```jsx
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature

def verify_MAC(key, signature, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(signature)
    except InvalidSignature:
        return False
    else:
        return True
```

**Modificirani sadržaj:**

```jsx
if __name__ == "__main__": 

	with open("doc.txt", "rb") as file: 
	message = file.read() 
	with open("doc.sig", "rb") as file: 
	signature = file.read() 
	key = b"lol" 
	provjera = verify_MAC(key, signature, mesage) 
	print(provjera) 
	# MAC = generate_MAC(key, content) # 
	with open("doc.sig", "wb") as file: #     
	file.write(MAC)
```

## 2. Izazov

U ovom izazovu **želimo utvrditi vremenski ispravnu sekvencu transakcija (ispravan redosljed transakcija) sa odgovarajućim dionicama**. Digitalno potpisani (primjenom MAC-a) nalozi za pojedine transakcije nalaze se na lokalnom web poslužitelju: [http://a507-server.local](http://a507-server.local/). Pomoću wget programa smo skinuli naš izazov.

Ključ je naše ime i prezime.

**CODE:**

```
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature

def generate_MAC(key, message):
    if not isinstance(message, bytes):
        message = message.encode()
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    signature = h.finalize()
    return signature

def verify_MAC(key, signature, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(signature)
    except InvalidSignature:
        return False
    else:
        return True

if __name__ == "__main__":
	
    **for ctr in range(1,11):
        msg_filename = f"order_{ctr}.txt"
        sig_filename = f"order_{ctr}.sig"
        with open(msg_filename, "rb") as file:
            content = file.read()
        with open(sig_filename, "rb") as file:
            signature = file.read()

        key = "mamic_rosana".encode()
        is_authentic = verify_MAC(key, signature, content)

	print(f'Message {content.decode():>45} {"OK" if is_authentic else "NOK":<6
```

## 3. Izazov

U ovom izazovu smo trebali odrediti autentičnu sliku (između dvije ponuđene) koju je profesor potpisao svojim privatnim ključem. Odgovarajući javni ključ dostupan je na određenom serveru.

**CODE:**

```jsx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

#Kako učitati javni ključ iz datoteke?
def load_public_key():
	with open("public.pem", "rb") as f:
	PUBLIC_KEY = serialization.load_pem_public_key(
	f.read(),
	backend=default_backend()
	)
	return PUBLIC_KEY

#Kako provjeriti ispravnost digitalnog potpisa?
def verify_signature_rsa(signature, message):
	PUBLIC_KEY = load_public_key()
	try:
	PUBLIC_KEY.verify(signature,message,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
	except InvalidSignature:
	return False
	else:
	return True

# Reading from a file
	with open("image_1.png", "rb") as file:
	image = file.read()

	with open("image_1.sig", "rb") as file:
	signature = file.read()

	is_authentic = verify_signature_rsa(signature, image)
	print(is_authentic)
```

# 4.Laboratorijska vježba

30.11.2021.

## **Password-hashing (iterative hashing, salt, memory-hard functions)**

```jsx
from os import urandom
from prettytable import PrettyTable
from timeit import default_timer as time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from passlib.hash import sha512_crypt, pbkdf2_sha256, argon2

def time_it(function):
def wrapper(*args, **kwargs):
start_time = time()
result = function(*args, **kwargs)
end_time = time()
measure = kwargs.get("measure")
if measure:
execution_time = end_time - start_time
return result, execution_time
return result
return wrapper

@time_it
def aes(**kwargs):
key = bytes([
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
])

plaintext = bytes([
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
])

encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
encryptor.update(plaintext)
encryptor.finalize()

@time_it
def md5(input, **kwargs):
digest = hashes.Hash(hashes.MD5(), backend=default_backend())
digest.update(input)
hash = digest.finalize()
return hash.hex()

@time_it
def sha256(input, **kwargs):
digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
digest.update(input)
hash = digest.finalize()
return hash.hex()

@time_it
def sha512(input, **kwargs):
digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
digest.update(input)
hash = digest.finalize()
return hash.hex()

@time_it
def pbkdf2(input, **kwargs):
# For more precise measurements we use a fixed salt
salt = b"12QIp/Kd"
rounds = kwargs.get("rounds", 10000)
return pbkdf2_sha256.hash(input, salt=salt, rounds=rounds)

@time_it
def argon2_hash(input, **kwargs):
# For more precise measurements we use a fixed salt
salt = b"0"*22
rounds = kwargs.get("rounds", 12) # time_cost
memory_cost = kwargs.get("memory_cost", 2**10) # kibibytes
parallelism = kwargs.get("rounds", 1)
return argon2.using(
salt=salt,
rounds=rounds,
memory_cost=memory_cost,
parallelism=parallelism
).hash(input)

@time_it
def linux_hash_6(input, **kwargs):
# For more precise measurements we use a fixed salt
salt = "12QIp/Kd"
return sha512_crypt.hash(input, salt=salt, rounds=5000)

@time_it
def linux_hash(input, **kwargs):
# For more precise measurements we use a fixed salt
salt = kwargs.get("salt")
rounds = kwargs.get("rounds", 5000)
if salt:
return sha512_crypt.hash(input, salt=salt, rounds=rounds)
return sha512_crypt.hash(input, rounds=rounds)

@time_it
def scrypt_hash(input, **kwargs):
salt = kwargs.get("salt", urandom(16))
length = kwargs.get("length", 32)
n = kwargs.get("n", 2**14)
r = kwargs.get("r", 8)
p = kwargs.get("p", 1)
kdf = Scrypt(
salt=salt,
length=length,
n=n,
r=r,
p=p
)
hash = kdf.derive(input)
return {
"hash": hash,
"salt": salt
}

if __name__ == "__main__":
ITERATIONS = 100
password = b"super secret password"

MEMORY_HARD_TESTS = []
LOW_MEMORY_TESTS = []

TESTS = [
{
"name": "AES",
"service": lambda: aes(measure=True)
},
{
"name": "HASH_MD5",
"service": lambda: sha512(password, measure=True)
},
{
"name": "HASH_SHA256",
"service": lambda: sha512(password, measure=True)
},
{
"name": "Linux CRYPT 5k",
"service": lambda: linux_hash(password, measure=True)
},
{
"name": "Linux CRYPT 1M",
"service": lambda: linux_hash(password, rounds=10**6, measure=True)
}
]

table = PrettyTable()
column_1 = "Function"
column_2 = f"Avg. Time ({ITERATIONS} runs)"
table.field_names = [column_1, column_2]
table.align[column_1] = "l"
table.align[column_2] = "c"
table.sortby = column_2

for test in TESTS:
name = test.get("name")
service = test.get("service")

total_time = 0
for iteration in range(0, ITERATIONS):
print(f"Testing {name:>6} {iteration}/{ITERATIONS}", end="\r")
_, execution_time = service()
total_time += execution_time
average_time = round(total_time/ITERATIONS, 6)
table.add_row([name, average_time])
print(f"{table}\n\n")
```

Uspoređivali smo brze i spore kriptografske hash-funkcije za sigurnu pohranu zaporki i izvođenje enkripcijskih ključeva. Sporije hash funkcije su sigurnije od brzih.