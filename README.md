# Post_Winstall
Powershell script for setting up Windows 10 and installing applications.

# Opis: 
Skripta za podesavanje sistema i instaliranje neophodnih aplikacija
na Windows 10 OS za klijentske racunare u okviru kompanije.

# Preduslov:
Kako biste mogli da koristite ovu skriptu, neophodno je da na racunaru
na kom ce se skripta izvrsavati pokrenete PowerShell sa administratorskim
privilegijama i uneste komandu Set-ExecutionPolicy RemoteSigned.
Takodje je neophodno da racunar ima pristup internet kako bi skripta mogla
da preuzme sve neophodne module i zakrpe.

# Koriscenje:
Nakon sto se ispunili sve preduslove, skriptu mozete pokrenuti dvoklikom
na njeno ime "Post_Winstall.ps1". Skriptu je moguce pokrenuti sa bilo koje
lokacije (C:\, USB...). 
Skripta ce izvrsiti sledece akcije na racunaru: 
Instalirace NuGet paket 
Obelezice PSGallery repozitorijum kao proveren 
Proverice internet konekciju
Instalirace modul za Windows Update
Importovace modul za Windows Update
Podesice vremensku zonu i format na srpsku latinicu
Ponudice opciju da se promeni ime racunara
Ponudice opciju da se ukljuci Administrator nalog i postavi sifra za isti
Dozvolice Remote Desktop i propustice ga kroz firewall
Ponudice opciju da se instaliraju neophodne aplikacije
Ponudice opciju da se racunar uclani u domen
Ponudice i proveriti da li je Windows licenciran i aktiviran
Ponudice opciju da azurira Windows zakrpe
Na kraju ce ponuditi opciju da se racunar restartuje
