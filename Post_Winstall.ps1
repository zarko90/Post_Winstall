##################################################################################################
#                                                                                                #
# Da bi ova skripta mogla normalno da radi, potrebno je pokrenuti PowerShell sa Admin            #
# privilegijama na racunaru na kom se skripta pokrece i pustiti sledecu komandu:                 #
#              Set-ExecutionPolicy RemoteSigned                                                  #
#                                                                                                #
##################################################################################################



#Proveravamo da li je skripta pokrenuta sa admin privilegijama, i ako nije, pokrecemo je ponovo
param([switch]$Elevated)

function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if ((Test-Admin) -eq $false)  {
    if ($elevated) {
        Write-Host "Nije moguce pokrenuti ovu skriptu pod Admin nalogom"
        Write-Host "Skripta ce prestati sa izvrsavanjem u naredne 3 sekunde"
        sleep 3
        Stop-Process -Id $PID
    } else {
        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
    }
    exit
}


#######################################################################################################################


#Instaliramo NuGet modul
Write-Host "Instaliram neophodne module za dalji rad skripte, molim za malo strpljenja..."
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force

#Dodajemo repozitorijum za Update modul u pouzdane i proverene repozitorijume
Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted


#######################################################################################################################


#Ovo bas i nije bilo neophodno, ali mislim da lepo izgleda :)
Write-Host "
*********************************************************************************
*                                                                               *
*                                                                               *
*                POST INSTALL SKRIPTA ZA WINDOWS 10 -ZARKO-                     *
*                                                                               *
*                                                                               *
*********************************************************************************
"
Write-Host ""
Write-Host ""
Write-Host "Skripta je pokrenuta sa punim privilegijama!"
Write-Host ""
sleep 2


#######################################################################################################################


#Testiramo internet konekciju
Write-Host "Testiramo internet konekciju, molim za malo strpljenja..."
Write-Host ""
$Konekcija = Test-Connection -ComputerName www.google.com -Quiet

if($Konekcija)
  {
    Write-Host "Racunar je povezan na mrezu!"
    Write-Host ""
  }
else
  {
    Write-Host "Racunar nije povezan na mrezu!"
    Write-Host "Skripta ce prestati sa izvrsavanjem u naredne 3 sekunde"
    sleep 3
    Stop-Process -Id $PID    
  }


#######################################################################################################################


#Instaliramo modul za update Windows-a
Install-Module PSWindowsUpdate

#Uvlacimo taj modul u Powershell kako bismo mogli da ga pokrenemo
Import-Module PSWindowsUpdate


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
         $ime = Read-Host "Unesite ime racunara"
         Rename-Computer -NewName $ime
         Remove-Variable odgovor
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

          #Unosimo sifru za nalog jednom, dobro obratite paznju sta i kako kucate posto se sifra unosi samo jednom i sakrivena je iza *
          $Password = Read-Host -AsSecureString -Prompt "Unesite sifru za Administrator nalog(vodite racuna jer se sifra unosi jednom)"

          #U promenljivu UserAccount uvozimo nalog za koji zelimo da se promeni sifra
          $UserAccount = Get-LocalUser -Name "Administrator"

          #Postavljamo sifru iz promenljive Password za nalog u promenljivoj UserAccount
          $UserAccount | Set-LocalUser -Password $Password

          #Uklanjamo promenljivu Password iz sigurnosnih razloga
          Remove-Variable Password
          Remove-Variable odgovor
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
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\' -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"


#######################################################################################################################


#Podesavamo vremensku zonu na CET+1 i sinhronizujemo vreme
Set-TimeZone -Id "Central Europe Standard Time"
W32tm /resync /force

#Podesavamo format na Srski/Latinica i lokaciju na Srbija
Set-WinHomeLocation -GeoId 0x10f
Set-WinSystemLocale -SystemLocale sr-Latn-RS
Set-Culture -CultureInfo sr-Latn-RS


#######################################################################################################################


#Pitamo korisnika da li zeli da instalira neophodne aplikacije
$ispravan_odgovor = $false
While (-not $ispravan_odgovor)
{
    $odgovor = Read-Host "Da li zelite da instalirate neophodne aplikacije?(d/n)"
    Switch($odgovor.ToLower())
    { "d"
       { $ispravan_odgovor = $true
         
		 #Podizemo file expolorer prozor u kom korisnik moze da odabere folder sa instalacijama
		 Function Select-FolderDialog
            {
                param([string]$Description="Izaberite folder u kom se nalaze instalacije",[string]$RootFolder="Desktop")

                [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null     

                $objForm = New-Object System.Windows.Forms.FolderBrowserDialog
                $objForm.Rootfolder = $RootFolder
                $objForm.Description = $Description
                $Show = $objForm.ShowDialog()
                if ($Show -eq "OK")
                {
                    Return $objForm.SelectedPath
                }
                else
                {
                    Write-Error "Operacija otkazana od strane korisnika."
                }
            }

         $folder = Select-FolderDialog

         #Instaliramo sve .exe aplikacije sa putanje promenljive $folder
         $installers = get-childitem "$folder" -Filter "*.exe"
         foreach($inst in $installers)
             {
              Start-Process -Wait -FilePath ($inst.FullName) -ArgumentList '/S' -PassThru
             }

         #Instaliramo sve .msi aplikacije iz INSTALL foldera
         $msiFiles = Get-ChildItem -Path "$folder" -Recurse -Include *.msi

         foreach ( $file in $msiFiles ) 
            {
             $fullPath = $file.FullName
             Write-Host "'$fullPath' se trenutno instalira..."
             Start-Process -FilePath msiexec.exe -ArgumentList "/I `"$fullPath`"","/quiet","ADDLOCAL=ALL","ALLUSERS=TRUE" -Wait
             Write-Host "$fullPath je uspesno instalirana!"
             Write-Host ""
            }
         
         Write-Host ""
         Write-Host "
         __________________________________________________
        |                                                  |
        |Molim vas da rucno instalirate OCS i AV aplikaciju|
        |__________________________________________________|

         "
         Write-Host ""
         sleep 5
         Remove-Variable odgovor
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
         
         #Dodajemo racunar na domen
         $domen = Read-Host "Uneseti ime domena na koji zelite da uclanite ovaj racunar"
         $korisnicko = Read-Host "Unesite korisnicko ime"
         Add-Computer -DomainName $domen -Credential $domen\$korisnicko
         Remove-Variable odgovor
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
         Write-Host "Proveravam Windows licencu, molim za malo strpljenja..."
         Write-Host ""
         #Proveravamo Windows licencu
         $SPL = Get-CimInstance -ClassName SoftwareLicensingProduct
         $WinProduct = $SPL | Where-Object Name -like "Windows*"
         if ($WinProduct.LicenseStatus -eq 1) 
            { 
               Write-Host "Windows je licenciran!"
               Remove-Variable odgovor 
            } 
         else 
            { 
               Write-Host "Windows nije licenciran!" 
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
         Write-Host "Molim za MNOGO strpljenja dok preuzmem i instaliram sve ispravke za Windows..."
         sleep 2
         Get-WindowsUpdate -AcceptAll -Install -IgnoreReboot
         Remove-Variable odgovor
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
Write-Host "Hvala Vam sto ste koristili skriptu!"
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
         ________________________________________________________________________________
        |                                                                                |
        | Molim vas da nakon restarta rucno instalirate OCS i AV app pod Admin nalogom!  |
        |________________________________________________________________________________|

         "
         Write-Host ""
         Write-Host "Restartujem racunar..."
         sleep 7
         Restart-Computer
       }
      "n"
       { $ispravan_odgovor = $true
         Write-Host ""
         Write-Host ""
         Write-Host "Zatvaram skriptu..."
         sleep 3
         Stop-Process -Id $PID
       }
   }
}
