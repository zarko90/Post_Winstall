##################################################################################################
#                                                                                                #
# Da bi ova skripta mogla normalno da radi, potrebno je pokrenuti PowerShell sa Admin            #
# privilegijama na racunaru na kom se skripta pokrece i pustiti sledecu komandu:                 #
#              Set-ExecutionPolicy RemoteSigned                                                  #
#                                                                                                #
##################################################################################################



#Proveravamo da li je skripta pokrenuta sa admin privilegijama, i ako nije, pokrecemo je ponovo
param([switch]$Elevated)

function Test-Admin 
{
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if ((Test-Admin) -eq $false)  
{
    if ($elevated) 
	{
        Write-Host "Nije moguce pokrenuti ovu skriptu pod Admin nalogom" -ForegroundColor Red
        Write-Host "Skripta ce prestati sa izvrsavanjem u naredne 3 sekunde" -ForegroundColor Yellow
        sleep 3
        Stop-Process -Id $PID
    } 
	else 
	{
        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
    }
	exit
}


#######################################################################################################################

clear
#Instaliramo NuGet modul
Write-Host "Instaliram neophodne module za dalji rad skripte, molim za malo strpljenja..." -ForegroundColor Yellow
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force *>$null

#Dodajemo repozitorijum za Update modul u pouzdane i proverene repozitorijume
Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted *>$null

#Instaliramo modul za update Windows-a
Install-Module PSWindowsUpdate *>$null

#Uvlacimo taj modul u Powershell kako bismo mogli da ga pokrenemo
Import-Module PSWindowsUpdate *>$null


#######################################################################################################################


#Ovo bas i nije bilo neophodno, ali mislim da lepo izgleda :)
clear
Write-Host "
*********************************************************************************
*                                                                               *
*                                                                               *
*                POST INSTALL SKRIPTA ZA WINDOWS 10 -ZARKO-                     *
*                                                                               *
*                                                                               *
*********************************************************************************
" -ForegroundColor Green
Write-Host ""
Write-Host ""
Write-Host "Skripta je pokrenuta sa punim privilegijama!" -ForegroundColor Yellow
Write-Host ""
sleep 2


#######################################################################################################################


#Testiramo internet konekciju
Write-Host "Testiram vezu sa mrezom, molim za malo strpljenja..." -ForegroundColor Yellow
Write-Host ""
$Konekcija = Test-Connection -ComputerName www.google.com -Quiet

if($Konekcija)
 {
     Write-Host "Racunar je povezan na mrezu!" -ForegroundColor Yellow
     Write-Host ""
 }
else
 {
     Write-Host "Racunar nije povezan na mrezu!" -ForegroundColor Red
	 Write-Host ""
	 Write-Host "Cekam na vezu sa mrezom." -NoNewLine -ForegroundColor Yellow
	 $timer = 0
	 do
	 {
		 Write-Host "." -NoNewLine -ForegroundColor Yellow
		 $timer += 1
		 
	 } until ($timer -eq 60 -or $Konekcija -eq $true )
	 Write-Host ""
     
	 Write-Host "Veza sa mrezom nije uspostavljena, zatvaram skriptu..." -ForegroundColor Red
     sleep 3
     Stop-Process -Id $PID    
 }


#######################################################################################################################


#Pitamo korisnika da li zeli da promeni ime racunara
$ispravan_odgovor = $false
While (-not $ispravan_odgovor)
{
     $odgovor = Read-Host "Da li zelite da promeni ime racunara?(d/n)"
     Switch($odgovor.ToLower())
     { "d"
         { $ispravan_odgovor = $true
         
             Write-Host ""
             #Menjamo ime racunara, ovde je neophodno da korisnik unese ime racunara kako bi skripta nastavila dalje
             $ime = Read-Host "Unesite ime racunara: "
             Rename-Computer -NewName $ime
         }
       "n"
         { $ispravan_odgovor = $true
             Write-Host ""
             break
         }
     }   
}


#######################################################################################################################


#Pitamo korisnika da li zeli da aktivira Admin nalog
$ispravan_odgovor = $false
While (-not $ispravan_odgovor)
{    
     $odgovor = Read-Host "Da li zelite da omogucite Administrator nalog?(d/n)"
     Switch($odgovor.ToLower())
     { "d"
         { $ispravan_odgovor = $true
		     Write-Host ""
    	     #Ukljucujemo ugradjeni Admin nalog
    	     Get-LocalUser -Name "Administrator" | Enable-LocalUser

             #Unosimo sifru za Administrator nalog
		     while($true)
		     {
		         $Password1 = Read-Host -AsSecureString -Prompt "Unesite sifru za Administrator nalog: "
		         $Password2 = Read-Host -AsSecureString -Prompt "Unesite jos jednom sifru za Administrator nalog: "
			  
			     #Vracamo promenljive iz secure string u normalni string radi daljeg uporedjivanja
		         $pwd1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password1))
                 $pwd2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password2))
	          
			     #Proveravamo da li se sifre poklapaju
			     if($pwd1 -ceq $pwd2)
                 {
                     #U promenljivu UserAccount uvozimo nalog za koji zelimo da se promeni sifra
                     $UserAccount = Get-LocalUser -Name "Administrator"
                 
                     #Postavljamo sifru iz promenljive Password za nalog u promenljivoj UserAccount
                     $UserAccount | Set-LocalUser -Password $Password2
                    
                     break
		         }
                 else
			     {
			         Write-Host "Sifre se ne poklapaju, pokusajte ponovo!" -ForegroundColor Red
			         sleep 2
			     }
		     }
         }
      "n"
         { $ispravan_odgovor = $true
             Write-Host ""
             break
         }
     }
}


#######################################################################################################################


#Omogucujemo Remote Desktop i propustamo ga kroz firewall
Write-Host ""
Write-Host "Pokrecem Remote Desktop servis i dozvoljavam mu pristup u firewall-u!" -ForegroundColor Yellow
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\' -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
Write-Host ""

#######################################################################################################################


#Podesavamo vremensku zonu na CET+1 i sinhronizujemo vreme
Write-Host "Podesavam vremensku zonu i sinhronizujem vreme!" -ForegroundColor Yellow
Set-TimeZone -Id "Central Europe Standard Time"
W32tm /resync /force *>$null
Write-Host ""

#Podesavamo format na Srski/Latinica i lokaciju na Srbija
Write-Host "Podesavam format i lokalizaciju na srpski jezik!" -ForegroundColor Yellow
Set-WinHomeLocation -GeoId 0x10f
Set-WinSystemLocale -SystemLocale sr-Latn-RS
Set-Culture -CultureInfo sr-Latn-RS
Write-Host ""

#######################################################################################################################


#Pitamo korisnika da li zeli da instalira neophodne aplikacije
$ispravan_odgovor = $false
While (-not $ispravan_odgovor)
{
     $odgovor = Read-Host "Da li zelite da instalirate neophodne aplikacije?(d/n)"
     Switch($odgovor.ToLower())
     { "d"
         { $ispravan_odgovor = $true
             
             #Instaliramo chocolatey za instalaciju aplikacija
             [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iwr https://community.chocolatey.org/install.ps1 -UseBasicParsing | iex *>$null
             sleep 5
             
             #Instaliramo podrazumevane aplikacije sa spiska ispod
             $packets = @("adobereader","7zip.install","putty.install","winscp.install","onlyoffice")
             Write-Host ""
             Write-Host "Zapocinjem instaliranje neophodnih aplikacija!" -ForegroundColor Yellow
             Write-Host ""
             sleep 1
             foreach($app in $packets)
             {
                 Write-Host "Instaliram $app!"
                 choco install $app -y *>$null
                 Write-Host ""
             }
         
             Write-Host ""
             Write-Host "
             ....................................................................
             .                                                                  .
             .  Molim vas da rucno instalirate OCS, AV i Cisco VPN aplikaciju!  .
             ....................................................................

             " -ForegroundColor Red
             Write-Host ""
             sleep 5

             #Pokusavamo da uklonimo chocolatey sa sistema
             $VerbosePreference = 'Continue'
             $userKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
             $userPath = $userKey.GetValue('PATH', [string]::Empty, 'DoNotExpandEnvironmentNames').ToString()
             $machineKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\ControlSet001\Control\Session Manager\Environment\', $true)
             $machinePath = $machineKey.GetValue('PATH', [string]::Empty, 'DoNotExpandEnvironmentNames').ToString()
             $backupPATHs = @(
             "User PATH: $userPath"
             "Machine PATH: $machinePath"
             )

             if ($userPath -like "*$env:ChocolateyInstall*") 
			 {
                 $newUserPATH = @(
                 $userPath -split [System.IO.Path]::PathSeparator |
                 Where-Object { $_ -and $_ -ne "$env:ChocolateyInstall\bin" }
                 ) -join [System.IO.Path]::PathSeparator
                 $userKey.SetValue('PATH', $newUserPATH, 'ExpandString')
             }

             if ($machinePath -like "*$env:ChocolateyInstall*") 
			 {
                 $newMachinePATH = @(
                 $machinePath -split [System.IO.Path]::PathSeparator |
                 Where-Object { $_ -and $_ -ne "$env:ChocolateyInstall\bin" }
                 ) -join [System.IO.Path]::PathSeparator
                 $machineKey.SetValue('PATH', $newMachinePATH, 'ExpandString')
             }

             $agentService = Get-Service -Name chocolatey-agent -ErrorAction SilentlyContinue
             if ($agentService -and $agentService.Status -eq 'Running') 
			 {
                 $agentService.Stop()
             }

             Remove-Item -Path $env:ChocolateyInstall -Recurse -Force

             'ChocolateyInstall', 'ChocolateyLastPathUpdate' | ForEach-Object {
                 foreach ($scope in 'User', 'Machine') {
                     [Environment]::SetEnvironmentVariable($_, [string]::Empty, $scope)
                 }
             }

             $machineKey.Close()
             $userKey.Close()
         }
      "n"
         { $ispravan_odgovor = $true
             Write-Host ""
             break
         }
     }
}


#######################################################################################################################


#Pitamo korisnika da li zeli da uclani racunar u domen
$ispravan_odgovor = $false
While (-not $ispravan_odgovor)
{
	 $odgovor = Read-Host "Da li zelite da uclanite racunar u domen?(d/n)"
     Switch($odgovor.ToLower())
     { "d"
         { $ispravan_odgovor = $true
             
			 Write-Host ""
             $domen = Read-Host "Uneseti ime domena na koji zelite da uclanite ovaj racunar"
             Write-Host ""
             #Proveravamo mreznu dostupnost unetog domena
			 Write-Host "Proveravam da li je domen dostupan..." -ForegroundColor Yellow
             Write-Host ""
	         $konekcija = Test-Connection -ComputerName $domen -Quiet

             if($konekcija)
             {
				 Write-Host "Pristupam domenu..." -ForegroundColor Yellow
				 sleep 1
                 $korisnicko = Read-Host "Unesite korisnicko ime"
                 Add-Computer -DomainName $domen -Credential $domen\$korisnicko
                 Write-Host ""
		         break
	         }
	         else
	         {
		         Write-Host "Uneti domen nije dostupan ili ne postoji!" -ForegroundColor Red
		         Write-Host ""
                 sleep 2
        
                 $pod_odgovor = $false 

                 while(-not $pod_odgovor)
                 {
                     $pod_pitanje = Read-Host "Da li zelite da pokusate ponovo?(d/n)"
                     Write-Host ""
                     Switch($pod_pitanje.ToLower())
                     { "d"
                         { $pod_odgovor = $true
                             break
                     }
                       "n"
                         { $pod_odgovor = $true
                             $ispravan_odgovor = $true
                             Write-Host ""
                         }
                     }
                 }
             }	 
         }
      "n"
         { $ispravan_odgovor = $true
             Write-Host ""
             break
         }
     }
}


#######################################################################################################################


#Pitamo korisnika da li zeli da aktivira Windows
$ispravan_odgovor = $false
While (-not $ispravan_odgovor)
{
     $odgovor = Read-Host "Da li zelite da proverite Windows licencu?(d/n)"
     Switch($odgovor.ToLower())
     { "d"
         { $ispravan_odgovor = $true
         
             Write-Host ""
             Write-Host "Proveravam Windows licencu, molim za malo strpljenja..." -ForegroundColor Yellow
             Write-Host ""
             #Proveravamo Windows licencu
             $SPL = Get-CimInstance -ClassName SoftwareLicensingProduct *>$null
             $WinProduct = $SPL | Where-Object Name -like "Windows*"
             if ($WinProduct.LicenseStatus -eq 1) 
             { 
                 Write-Host "Windows je licenciran!" -ForegroundColor Yellow
             } 
             else 
             { 
                 Write-Host "Windows nije licenciran!" -ForegroundColor Red
                 Write-Host ""
                 $pod_odgovor = $false
         
		 		 While (-not $pod_odgovor)
		   		 {
             		 #Pitamo korisnika da li zeli da aktivira Windows
			 	     $pitanje = Read-Host "Da li zelite rucno da aktivirate Windows?(d/n)"
             		 Switch($pitanje.ToLower())
             			 { "d"
                   		     { $pod_odgovor = $true
				                 #Podizemo prozor u kom korisnik moze da unese kljuc
                      		     slui.exe
                   		     }
                  		   "n"
                   		     { $pod_odgovor = $true
                     		     Write-Host ""
                     		     break
                   		     }
               		     }
           		 }
             }
         }
      "n"
         { $ispravan_odgovor = $true
             Write-Host ""
             break
         }
     }
}


#######################################################################################################################


#Pitamo korisnika da li zeli da update-uje Windows
$ispravan_odgovor = $false
While (-not $ispravan_odgovor)
{
     $odgovor = Read-Host "Da li zelite da azurirate Windows?(d/n)"
     Switch($odgovor.ToLower())
     { "d"
         { $ispravan_odgovor = $true

	         #Skidamo sve dostupne update za sistem i instaliramo ih
             Write-Host ""
             Write-Host "Molim za MNOGO strpljenja dok preuzmem i instaliram sve ispravke za Windows..." -ForegroundColor Yellow
             sleep 2
             Get-WindowsUpdate -AcceptAll -Install -IgnoreReboot *>$null
         }
      "n"
         { $ispravan_odgovor = $true
             Write-Host ""
             break
         }
     }
}


#######################################################################################################################


#Pitamo korisnika da li zeli da restartuje racunar
Write-Host ""
Write-Host "Hvala Vam sto ste koristili skriptu!" -ForegroundColor Yellow
Write-Host ""
Write-Host ""
$ispravan_odgovor = $false
While (-not $ispravan_odgovor)
{
     $odgovor = Read-Host "Da li zelite da restartujete racunar kako bi sve izmene bile primenjene?(d/n)"
     Switch($odgovor.ToLower())
     { "d"
         { $ispravan_odgovor = $true
	         Write-Host ""
             Write-Host "
             ....................................................................
             .                                                                  .
             .  Molim vas da rucno instalirate OCS, AV i Cisco VPN aplikaciju!  .
             ....................................................................

             " -ForegroundColor Red
             Write-Host ""
             Write-Host "Restartujem racunar..." -ForegroundColor Yellow
             sleep 4

             #Iz bezbednosnih razloga vracamo polisu na podrazumevana podesavanja
             Set-ExecutionPolicy Restricted
         
             Restart-Computer
         }
      "n"
         { $ispravan_odgovor = $true
             Write-Host ""
             Write-Host "
             ....................................................................
             .                                                                  .
             .  Molim vas da rucno instalirate OCS, AV i Cisco VPN aplikaciju!  .
             ....................................................................
             " -ForegroundColor Red
             sleep 5
             Write-Host ""
             Write-Host ""
             Write-Host "Zatvaram skriptu..." -ForegroundColor Yellow
             sleep 3
         
             #Iz bezbednosnih razloga vracamo polisu na podrazumevana podesavanja
             Set-ExecutionPolicy Restricted
         
             Stop-Process -Id $PID
         }
     }
}