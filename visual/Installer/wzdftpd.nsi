;--------------------------------------------------------------------------------
; WZDFTPD Install Script
; http://www.wzdftpd.net/
; Uses NSIS Script by Nulsoft - http://nsis.sourceforge.net/
; NSIS Script written by javsmo@users.sourceforge.net (Jose Antonio Oliveira)
; Project Developer (pollux@cpe.fr)
; Creation date: Nov-07-2004
; Last Modified: Mar-19-2005


;--------------------------------
;Include section
  !include "MUI.nsh"
  !include "AdvancedReplace.nsi"

;--------------------------------
;Constants
  !define VER_DISPLAY "0.5.1"
  !define FILE_ROOT "..\files\"
  !define PROG_NAME "wzdftpd"
  !define LICENSE_FILE "LICENSE.TXT"
  !define WEBSITE_URL "http://www.wzdftpd.net/"
  
  ;Paths to the source files (Don't forget the final "\")
  !define RELEASE_DIR "..\release\"
  !define LIBWZD_RELEASE_DIR "..\libwzd\release\"
  !define LIBWZD-AUTH_RELEASE_DIR "..\libwzd-auth\release\"
  !define LIBWZD-BASE_RELEASE_DIR "..\libwzd-base\release\"
  !define GNU_REGEX_DIST_DIR "..\gnu_regex_dist\"
  !define ICONV_BIN_DIR "..\iconv\bin\"
  !define OPENSSL_LIB_DIR "..\openssl\lib\"
  !define ZLIB_DIR "..\zlib\"
  !define SRC_DIR "..\..\src\"
  !define ROOT_DIR "..\..\"
  !define DOT_DOT_DIR "..\"
  !define BACKEND_MYSQL_RELEASE_DIR "..\backends\mysql\release\"
  !define BACKEND_PLAINTEXT_RELEASE_DIR "..\backends\plaintext\release\"
  !define TOOLS_SITECONFIG_RELEASE_DIR "..\tools\siteconfig\release\"
  !define TOOLS_SITEUPTIME_RELEASE_DIR "..\tools\siteuptime\release\"
  !define TOOLS_SITEWHO_RELEASE_DIR "..\tools\sitewho\release\"
  !define MODULES_TCL_RELEASE_DIR "..\modules\tcl\release\"
  !define MODULES_PERL_RELEASE_DIR "..\modules\perl\release\"
  !define MODULES_SFV_RELEASE_DIR "..\modules\sfv\release\"
  !define MODULES_DEVELOP_DIR "..\src\"
  !define MODULES_DEVELOP_LIB_DIR "..\src\"

  !define PROG_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROG_NAME}"
  !define PROG_UNINST_ROOT_KEY "HKLM"
  
 Function GetWindowsVersion
   Push $R0
   Push $R1
   ReadRegStr $R0 HKLM \
   "SOFTWARE\Microsoft\Windows NT\CurrentVersion" CurrentVersion
   IfErrors 0 lbl_winnt
   ; we are not NT
   ReadRegStr $R0 HKLM \
   "SOFTWARE\Microsoft\Windows\CurrentVersion" VersionNumber
   StrCpy $R1 $R0 1
   StrCmp $R1 '4' 0 lbl_error
   StrCpy $R1 $R0 3
   StrCmp $R1 '4.0' lbl_win32_95
   StrCmp $R1 '4.9' lbl_win32_ME lbl_win32_98
   lbl_win32_95:
     StrCpy $R0 '95'
   Goto lbl_done
   lbl_win32_98:
     StrCpy $R0 '98'
   Goto lbl_done
   lbl_win32_ME:
     StrCpy $R0 'ME'
   Goto lbl_done
   lbl_winnt:
   StrCpy $R1 $R0 1
   StrCmp $R1 '3' lbl_winnt_x
   StrCmp $R1 '4' lbl_winnt_x
   StrCpy $R1 $R0 3
   StrCmp $R1 '5.0' lbl_winnt_2000
   StrCmp $R1 '5.1' lbl_winnt_XP
   StrCmp $R1 '5.2' lbl_winnt_2003 lbl_error
   lbl_winnt_x:
     StrCpy $R0 "NT $R0" 6
   Goto lbl_done
   lbl_winnt_2000:
     Strcpy $R0 '2000'
   Goto lbl_done
   lbl_winnt_XP:
     Strcpy $R0 'XP'
   Goto lbl_done
   lbl_winnt_2003:
     Strcpy $R0 '2003'
   Goto lbl_done
   lbl_error:
     Strcpy $R0 ''
   lbl_done:
   Pop $R1
   Exch $R0
 FunctionEnd
 
 Function GetWindowsFamily
  Call GetWindowsVersion
  Pop $R0
  StrCmp $R0 'NT 3.5' lbl_nt_family
  StrCmp $R0 'NT 4.0' lbl_nt_family
  StrCmp $R0 '2000' lbl_nt_family
  StrCmp $R0 'XP' lbl_nt_family
  StrCmp $R0 '2003' lbl_nt_family
  StrCmp $R0 '95' lbl_9x_family
  StrCmp $R0 '98' lbl_9x_family
  StrCmp $R0 'ME' lbl_9x_family
  lbl_nt_family:
    StrCpy $R0 'NT'
  Goto done_family
  lbl_9x_family:
    StrCpy $R0 '9X'
  done_family:
  Push $R0
 FunctionEnd
 
;--------------------------------
;Variables
Var STARTMENU_FOLDER
Var WindowsFamily

;Name and output file
  Name ${PROG_NAME}
  OutFile "${PROG_NAME}-${VER_DISPLAY}.exe" 
  SetCompressor lzma
  
  ;Default installation folder
  InstallDir "$PROGRAMFILES\${PROG_NAME}"
  
  ;Get installation folder from registry if available
  InstallDirRegKey HKCU "Software\${PROG_NAME}" ""
  
  ;Other Options
  ShowInstDetails show
  ShowUnInstDetails show

;--------------------------------
;Interface Settings
  !define MUI_HEADERIMAGE
  !define MUI_ABORTWARNING


;--------------------------------
;Language Selection Dialog Settings
  ;Remember the installer language
  !define MUI_LANGDLL_REGISTRY_ROOT "HKCU" 
  !define MUI_LANGDLL_REGISTRY_KEY "Software\${PROG_NAME}" 
  !define MUI_LANGDLL_REGISTRY_VALUENAME "Installer Language"

;--------------------------------
;Pages
  !insertmacro MUI_PAGE_WELCOME
  !insertmacro MUI_PAGE_LICENSE ${LICENSE_FILE}
  !insertmacro MUI_PAGE_COMPONENTS
  !insertmacro MUI_PAGE_DIRECTORY

  ;Start Menu Folder Page Configuration
  !define MUI_STARTMENUPAGE_REGISTRY_ROOT "HKCU" 
  !define MUI_STARTMENUPAGE_REGISTRY_KEY "Software\${PROG_NAME}" 
  !define MUI_STARTMENUPAGE_REGISTRY_VALUENAME "Start Menu Folder"
  !insertmacro MUI_PAGE_STARTMENU Application $STARTMENU_FOLDER
  
  !insertmacro MUI_PAGE_INSTFILES
  
  ;Finish Page with wzdftpd website URL
  !define MUI_FINISHPAGE_LINK $(DESC_Link_Finish)
  !define MUI_FINISHPAGE_LINK_LOCATION "http://www.wzdftpd.net/"
  
  !define MUI_FINISHPAGE_NOREBOOTSUPPORT
  !insertmacro MUI_PAGE_FINISH

  
  !insertmacro MUI_UNPAGE_CONFIRM
  !insertmacro MUI_UNPAGE_INSTFILES

;--------------------------------
;Languages
  !insertmacro MUI_LANGUAGE "German" ;Deutsch
  !insertmacro MUI_LANGUAGE "English" ;English
  !insertmacro MUI_LANGUAGE "Spanish" ;Espanol
  !insertmacro MUI_LANGUAGE "French" ;Francais
  !insertmacro MUI_LANGUAGE "Italian" ;Italiano
  !insertmacro MUI_LANGUAGE "Portuguese" ;Portugues
  !insertmacro MUI_LANGUAGE "PortugueseBR" ;Portugues (Brasil)
  
  ;--------------------------------
  ; Languages String Table
  ;English
  LangString DESC_MainSec ${LANG_ENGLISH} "Main program and all needed files. Includes Plain-Text backend."
  LangString DESC_TCLSec ${LANG_ENGLISH} "Optional TCL Modules."
  LangString DESC_PerlSec ${LANG_ENGLISH} "Optional Perl Modules."
  LangString DESC_MySQLSec ${LANG_ENGLISH} "Optional MySQL Backend."
  LangString DESC_DevelopSec ${LANG_ENGLISH} "Installs all headers and libraries needed by developers."
  LangString CAPT_MainSec ${LANG_ENGLISH} "Main Program"
  LangString CAPT_TCLSec  ${LANG_ENGLISH} "TCL Modules"
  LangString CAPT_PerlSec ${LANG_ENGLISH} "Perl Modules"  
  LangString CAPT_MySQLSec ${LANG_ENGLISH} "MySQL Backend"
  LangString CAPT_DevelopSec ${LANG_ENGLISH} "Developer Module"
  LangString DESC_Link_Finish ${LANG_ENGLISH} "Visit the wzdftpd site for the latest news, FAQs and support"
  LangString DESC_Detail_Print ${LANG_ENGLISH} "Installing Core Files..."
  
  ;French
  LangString DESC_MainSec ${LANG_FRENCH} "Programme principal et tous dossiers nécessaires. Inclut le plain-Text backend."
  LangString DESC_TCLSec ${LANG_FRENCH} "Modules TCL facultatifs."
  LangString DESC_PerlSec ${LANG_FRENCH} "Modules Perl facultatifs."
  LangString DESC_MySQLSec ${LANG_FRENCH} "Backend MySQL facultatif."
  LangString DESC_DevelopSec ${LANG_FRENCH} "Installe tous les en-têtes et bibliothèques requis par des développeurs."
  LangString CAPT_MainSec ${LANG_FRENCH} "Programme Principal"
  LangString CAPT_TCLSec  ${LANG_FRENCH} "Modules TCL"
  LangString CAPT_PerlSec ${LANG_FRENCH} "Modules Perl"  
  LangString CAPT_MySQLSec ${LANG_FRENCH} "Module MySQL"
  LangString CAPT_DevelopSec ${LANG_FRENCH} "Module pur Développeur"
  LangString DESC_Link_Finish ${LANG_FRENCH} "Visitez l'emplacement de wzdftpd pour les derniers nouvelles, FAQ et appui."
  LangString DESC_Detail_Print ${LANG_FRENCH} "Installation des dossiers Principaux..."
  
  ;Brazilian Portuguese
  LangString DESC_MainSec ${LANG_PORTUGUESEBR} "Programa principal e todos os arquivos necessários. Inclui o driver para autenticação em texto."
  LangString DESC_TCLSec ${LANG_PORTUGUESEBR} "Módulos TCL opcionais."
  LangString DESC_PerlSec ${LANG_PORTUGUESEBR} "Módulos Perl opcionais."
  LangString DESC_MySQLSec ${LANG_PORTUGUESEBR} "Módulo de autenticação por MySQL."
  LangString DESC_DevelopSec ${LANG_PORTUGUESEBR} "Instala os cabeçalhos e bibliotecas necessárias ao desenvolvedor."
  LangString CAPT_MainSec ${LANG_PORTUGUESEBR} "Programa Principal"
  LangString CAPT_TCLSec  ${LANG_PORTUGUESEBR} "Módulos TCL"
  LangString CAPT_PerlSec ${LANG_PORTUGUESEBR} "Módulos Perl"  
  LangString CAPT_MySQLSec ${LANG_PORTUGUESEBR} "Módulo MySQL"
  LangString CAPT_DevelopSec ${LANG_PORTUGUESEBR} "Módulo Desenvolvedor"
  LangString DESC_Link_Finish ${LANG_PORTUGUESEBR} "Visite o site do wzdftpd para obter notícias, FAQs e suporte."
  LangString DESC_Detail_Print ${LANG_PORTUGUESEBR} "Instalação dos arquivos principais..."

  ;Portuguese
  LangString DESC_MainSec ${LANG_PORTUGUESE} "Programa principal e todos os ficheiros necessários. Inclui o driver para autenticação em texto."
  LangString DESC_TCLSec ${LANG_PORTUGUESE} "Módulos TCL opcionais."
  LangString DESC_PerlSec ${LANG_PORTUGUESE} "Módulos Perl opcionais."
  LangString DESC_MySQLSec ${LANG_PORTUGUESE} "Módulo de autenticação por MySQL."
  LangString DESC_DevelopSec ${LANG_PORTUGUESE} "Instala os cabeçalhos e bibliotecas necessárias ao desenvolvedor."
  LangString CAPT_MainSec ${LANG_PORTUGUESE} "Programa Principal"
  LangString CAPT_TCLSec  ${LANG_PORTUGUESE} "Módulos TCL"
  LangString CAPT_PerlSec ${LANG_PORTUGUESE} "Módulos Perl"  
  LangString CAPT_MySQLSec ${LANG_PORTUGUESE} "Módulo MySQL"
  LangString CAPT_DevelopSec ${LANG_PORTUGUESE} "Módulo Desenvolvedor"
  LangString DESC_Link_Finish ${LANG_PORTUGUESE} "Visite o sítio do wzdftpd para obter notícias, FAQs e suporte."
  LangString DESC_Detail_Print ${LANG_PORTUGUESE} "Instalação dos ficheiros principais..."
  
  ;Spanish
  LangString DESC_MainSec ${LANG_SPANISH} "Programa principal y todos los archivos necesarios. Incluye el plain-Text backend."
  LangString DESC_TCLSec ${LANG_SPANISH} "Módulos Opcionales del TCL"
  LangString DESC_PerlSec ${LANG_SPANISH} "Módulos Opcionales de Perl."
  LangString DESC_MySQLSec ${LANG_SPANISH} "Módulo de autenticación por MySQL."
  LangString DESC_DevelopSec ${LANG_SPANISH} "Instala todos los títulos y bibliotecas necesitados por los desarrolladores."
  LangString CAPT_MainSec ${LANG_SPANISH} "Programa Principal"
  LangString CAPT_TCLSec  ${LANG_SPANISH} "Módulos TCL"
  LangString CAPT_PerlSec ${LANG_SPANISH} "Módulos Perl"
  LangString CAPT_MySQLSec ${LANG_SPANISH} "Módulo MySQL"
  LangString CAPT_DevelopSec ${LANG_SPANISH} "Módulo Desarrollador"
  LangString DESC_Link_Finish ${LANG_SPANISH} "Visite el sitio del wzdftpd para las últimas noticias, y obtener ayuda"
  LangString DESC_Detail_Print ${LANG_SPANISH} "Instalando Archivos De Base..."
  
  ;German
  LangString DESC_MainSec ${LANG_GERMAN} "Hauptprogramm und alle erforderlichen Dateien. Umfaßt den Backend Klartext."
  LangString DESC_TCLSec ${LANG_GERMAN} "Wahlweise freigestellte TCL-Module."
  LangString DESC_PerlSec ${LANG_GERMAN} "Wahlweise freigestellte Perl-Module."
  LangString DESC_MySQLSec ${LANG_GERMAN} "Wahlweise MySQL Backend."
  LangString DESC_DevelopSec ${LANG_GERMAN} "Installiert alle Überschriften und Bibliotheken , die von Entwicklern benötigt werden."
  LangString CAPT_MainSec ${LANG_GERMAN} "HauptProgramm"
  LangString CAPT_TCLSec  ${LANG_GERMAN} "TCL-Module"
  LangString CAPT_PerlSec ${LANG_GERMAN} "TCL-Module"
  LangString CAPT_MySQLSec ${LANG_GERMAN} "MySQL Backend"
  LangString CAPT_DevelopSec ${LANG_GERMAN} "EntwicklerModul"
  LangString DESC_Link_Finish ${LANG_GERMAN} "Besuchen Sie den wzdftpdaufstellungsort für die neuesten Nachrichten, die FAQ und die Unterstützung"
  LangString DESC_Detail_Print ${LANG_GERMAN} "Dateien mit Speicherabzug installieren..."
  
  ;Italian
  LangString DESC_MainSec ${LANG_ITALIAN} "Programma principale e tutte le lime necessarie. Include il plain-Text backend."
  LangString DESC_TCLSec ${LANG_ITALIAN} "Moduli Facoltativi di TCL."
  LangString DESC_PerlSec ${LANG_ITALIAN} "Moduli Facoltativi Del Perl."
  LangString DESC_MySQLSec ${LANG_ITALIAN} "Moduli Facoltativi Del MySQL Backend."
  LangString DESC_DevelopSec ${LANG_ITALIAN} "Installa tutte le intestazioni e biblioteche necessarie dagli sviluppatori."
  LangString CAPT_MainSec ${LANG_ITALIAN} "Programma Principale"
  LangString CAPT_TCLSec  ${LANG_ITALIAN} "Moduli del TCL."
  LangString CAPT_PerlSec ${LANG_ITALIAN} "Moduli del Perl"
  LangString CAPT_MySQLSec ${LANG_ITALIAN} "Moduli MySQL"
  LangString CAPT_DevelopSec ${LANG_ITALIAN} "Modulo Di Sviluppatore"
  LangString DESC_Link_Finish ${LANG_ITALIAN} "Visiti il luogo del wzdftpd per le ultimi notizie, FAQ e supporto"
  LangString DESC_Detail_Print ${LANG_ITALIAN} "Installando Le Lime Di Nucleo..."


;--------------------------------
;Reserve Files
;These files should be inserted before other files in the data block
;Keep these lines before any File command
;Only for solid compression (by default, solid compression is enabled for BZIP2 and LZMA)
  
  !insertmacro MUI_RESERVEFILE_LANGDLL

;--------------------------------
;Installer Sections

Section "!$(CAPT_MainSec)" MainSec
;--------------------------------
;General & Initialization
  Call GetWindowsFamily
  Pop $WindowsFamily

  SetOutPath "$INSTDIR"
  DetailPrint $(DESC_DETAIL_PRINT)

  SetOverwrite off
  
  CreateDirectory "$INSTDIR\backends\"
  CreateDirectory "$INSTDIR\etc\"
  CreateDirectory "$INSTDIR\tools\"
  CreateDirectory "$INSTDIR\modules\"
  CreateDirectory "$INSTDIR\ftproot\"
  CreateDirectory "$INSTDIR\vfsroot\"
  CreateDirectory "$INSTDIR\logs\"
  
  ;Files
  SetOutPath "$INSTDIR"
  File "${RELEASE_DIR}wzdftpd.exe"
  File "${RELEASE_DIR}libwzd_core.dll"
  File "${LIBWZD_RELEASE_DIR}libwzd.dll"
  File "${GNU_REGEX_DIST_DIR}gnu_regex.dll"
  File "${ICONV_BIN_DIR}libiconv-2.dll"
  File "${OPENSSL_LIB_DIR}ssleay32.dll"
  File "${OPENSSL_LIB_DIR}libeay32.dll"
  File "${ZLIB_DIR}zlib1.dll"

  ;file_*.txt files
  SetOutPath "$INSTDIR\etc\"
  File /nonfatal "${SRC_DIR}file_ginfo.txt"
  File /nonfatal "${SRC_DIR}file_group.txt" 
  File /nonfatal "${SRC_DIR}file_groups.txt" 
  File /nonfatal "${SRC_DIR}file_help.txt" 
  File /nonfatal "${SRC_DIR}file_rules.txt" 
  File /nonfatal "${SRC_DIR}file_swho.txt" 
  File /nonfatal "${SRC_DIR}file_user.txt" 
  File /nonfatal "${SRC_DIR}file_users.txt" 
  File /nonfatal "${SRC_DIR}file_vfs.txt" 
  File /nonfatal "${SRC_DIR}file_who.txt" 

  ;Other files
  SetOutPath "$INSTDIR"
  File "${ROOT_DIR}AUTHORS"
  File "${ROOT_DIR}ChangeLog"
  File "${ROOT_DIR}COPYING"
  File "${ROOT_DIR}INSTALL"
  File "${ROOT_DIR}NEWS"
  File "${ROOT_DIR}Permissions.ReadMeFirst"
  File "${ROOT_DIR}README"
  File "${ROOT_DIR}TLS.ReadmeFirst"
  File "${ROOT_DIR}wzd_tls.cnf"
  File "${SRC_DIR}wzd.pem"
  File "${DOT_DOT_DIR}wzd.cfg"
  File "${DOT_DOT_DIR}users"

  ;Plain-Text backend
  SetOutPath "$INSTDIR\backends"
  File "${BACKEND_PLAINTEXT_RELEASE_DIR}libwzd_plaintext.dll"

  ;Tools
  SetOutPath "$INSTDIR\tools"
  File "${TOOLS_SITECONFIG_RELEASE_DIR}siteconfig.exe"
  File "${TOOLS_SITEUPTIME_RELEASE_DIR}siteuptime.exe"
  File "${TOOLS_SITEWHO_RELEASE_DIR}sitewho.exe"
  
  ;Mandatory Modules
  SetOutPath "$INSTDIR\modules"
  File /oname=$INSTDIR\modules\libwzd_sfv.dll "${MODULES_SFV_RELEASE_DIR}libwzd_sfv.dll"
  
  SetOutPath $INSTDIR

  ;Create the URL file to make the start menu link
  WriteIniStr "$INSTDIR\${PROG_NAME}.url" "InternetShortcut" "URL" "${WEBSITE_URL}"
  
  ;Store installation folder
  WriteRegStr HKCU "Software\${PROG_NAME}" "" $INSTDIR
  
  ;Create uninstaller
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  
  ;Create Shortcuts
  !insertmacro MUI_STARTMENU_WRITE_BEGIN Application
  CreateDirectory "$SMPROGRAMS\$STARTMENU_FOLDER"
  StrCpy $WindowsFamily 'NT'
    CreateShortCut "$SMPROGRAMS\$STARTMENU_FOLDER\Start Service ${PROG_NAME}.lnk" "$INSTDIR\${PROG_NAME}.exe" "-ss"
    CreateShortCut "$SMPROGRAMS\$STARTMENU_FOLDER\Stop Service ${PROG_NAME}.lnk" "$INSTDIR\${PROG_NAME}.exe" "-st"
    CreateShortCut "$SMPROGRAMS\$STARTMENU_FOLDER\Register Service ${PROG_NAME}.lnk" "$INSTDIR\${PROG_NAME}.exe" "-si"
    CreateShortCut "$SMPROGRAMS\$STARTMENU_FOLDER\Unregister Service ${PROG_NAME}.lnk" "$INSTDIR\${PROG_NAME}.exe" "-sd"
  Goto lbl_family1
  StrCpy $WindowsFamily '9X'
    CreateShortCut "$SMPROGRAMS\$STARTMENU_FOLDER\${PROG_NAME}.lnk" "$INSTDIR\${PROG_NAME}.exe"
  lbl_family1:
  CreateShortCut "$SMPROGRAMS\$STARTMENU_FOLDER\wzdftpd on the Web.lnk" "$INSTDIR\${PROG_NAME}.url"
  CreateShortCut "$SMPROGRAMS\$STARTMENU_FOLDER\Uninstall.lnk" "$INSTDIR\Uninstall.exe"
  !insertmacro MUI_STARTMENU_WRITE_END
  
  ;Modify the wzd.cfg and users files
  ;Starts with wzd.cfg file
  ;Replace c:\program files\wzdftpd\ by $INSTDIR
  Push "c:\program files\wzdftpd"
  Push $INSTDIR
  Push all
  Push all
  Push "$INSTDIR\wzd.cfg"
  Call AdvReplaceInFile

  ;Replace the "losts" c:\wzdftpd
  Push "c:\wzdftpd"
  Push $INSTDIR
  Push all
  Push all
  Push "$INSTDIR\wzd.cfg"
  Call AdvReplaceInFile

  ;Comments the two last lines :)
  Push "-site_my_free = *"
  Push "# -site_my_free = *"
  Push all
  Push all
  Push "$INSTDIR\wzd.cfg"
  Call AdvReplaceInFile

  ;Comments the two last lines :)
  Push "-site_test = =pollux"
  Push "# -site_my_free = *"
  Push all
  Push all
  Push "$INSTDIR\wzd.cfg"
  Call AdvReplaceInFile

  ;Now it's time to modify the users file
  ;Replace c:\program files\wzdftpd\ by $INSTDIR
  Push "c:\program files\wzdftpd"
  Push $INSTDIR
  Push all
  Push all
  Push "$INSTDIR\users"
  Call AdvReplaceInFile
SectionEnd

;------------------
;SECTION -POST
;------------------

Section -Post
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  WriteRegStr HKLM "Software\${PROG_NAME}" "" "$INSTDIR\wzdftpd.exe"
  WriteRegStr ${PROG_UNINST_ROOT_KEY} "${PROG_UNINST_KEY}" "DisplayName" "$(^Name)"
  WriteRegStr ${PROG_UNINST_ROOT_KEY} "${PROG_UNINST_KEY}" "UninstallString" "$INSTDIR\Uninstall.exe"
  WriteRegStr ${PROG_UNINST_ROOT_KEY} "${PROG_UNINST_KEY}" "DisplayIcon" "$INSTDIR\wzdftpd.exe"
  WriteRegStr ${PROG_UNINST_ROOT_KEY} "${PROG_UNINST_KEY}" "DisplayVersion" "${VER_DISPLAY}"
  WriteRegStr ${PROG_UNINST_ROOT_KEY} "${PROG_UNINST_KEY}" "URLInfoAbout" "${WEBSITE_URL}"
  ;register and start service
  ExecWait '"$INSTDIR\${PROG_NAME}.exe" -si' $0
  ;ExecWait '"$SYSDIR\net" start wzdftpd' $0
SectionEnd

;---------------
;TCL Section
;---------------

Section /o $(CAPT_TCLSec) TCLSec
  SetOutPath "$INSTDIR\modules"
  File "${MODULES_TCL_RELEASE_DIR}libwzd_tcl.dll"
SectionEnd

Section /o $(CAPT_PerlSec) PerlSec
  SetOutPath "$INSTDIR\modules"
  File "${MODULES_PERL_RELEASE_DIR}libwzd_perl.dll"
SectionEnd

Section /o $(CAPT_MySQLSec) MySQLSec
  SetOutPath "$INSTDIR\backends"
  File "${BACKEND_MYSQL_RELEASE_DIR}libwzd_mysql.dll"
SectionEnd

Section /o $(CAPT_DevelopSec) DevelopSec
  ;Create the destination folders
  CreateDirectory "$INSTDIR\include\"
  CreateDirectory "$INSTDIR\lib\"

  ;Copy Files to destination
  SetOutPath "$INSTDIR\include"
  File "${SRC_DIR}ls.h"
  File "${SRC_DIR}wzd_action.h"
  File "${SRC_DIR}wzd_all.h"
  File "${SRC_DIR}wzd_backend.h"
  File "${SRC_DIR}wzd_cache.h"
  File "${SRC_DIR}wzd_ClientThread.h"
  File "${SRC_DIR}wzd_commands.h"
  File "${SRC_DIR}wzd_crc32.h"
  File "${SRC_DIR}wzd_crontab.h"
  File "${SRC_DIR}wzd_data.h"
  File "${SRC_DIR}wzd_debug.h"
  File "${SRC_DIR}wzd_dir.h"
  File "${SRC_DIR}wzd_file.h"
  File "${SRC_DIR}wzd_hardlimits.h"
  File "${SRC_DIR}wzd_init.h"
  File "${SRC_DIR}wzd_ip.h"
  File "${SRC_DIR}wzd_libmain.h"
  File "${SRC_DIR}wzd_log.h"
  File "${SRC_DIR}wzd_messages.h"
  File "${SRC_DIR}wzd_misc.h"
  File "${SRC_DIR}wzd_mod.h"
  File "${SRC_DIR}wzd_mutex.h"
  File "${SRC_DIR}wzd_opts.h"
  File "${SRC_DIR}wzd_perm.h"
  File "${SRC_DIR}wzd_ratio.h"
  File "${SRC_DIR}wzd_savecfg.h"
  File "${SRC_DIR}wzd_section.h"
  File "${SRC_DIR}wzd_ServerThread.h"
  File "${SRC_DIR}wzd_shm.h"
  File "${SRC_DIR}wzd_site.h"
  File "${SRC_DIR}wzd_site_group.h"
  File "${SRC_DIR}wzd_site_user.h"
  File "${SRC_DIR}wzd_socket.h"
  File "${SRC_DIR}wzd_string.h"
  File "${SRC_DIR}wzd_strptime.h"
  File "${SRC_DIR}wzd_strtoull.h"
  File "${SRC_DIR}wzd_structs.h"
  File "${SRC_DIR}wzd_tls.h"
  File "${SRC_DIR}wzd_types.h"
  File "${SRC_DIR}wzd_utf8.h"
  File "${SRC_DIR}wzd_vars.h"
  File "${SRC_DIR}wzd_vfs.h"
  
  SetOutPath "$INSTDIR\lib"
  File "${BACKEND_MYSQL_RELEASE_DIR}libwzd_mysql.lib"
  File "${BACKEND_PLAINTEXT_RELEASE_DIR}libwzd_plaintext.lib"
  File "${LIBWZD_RELEASE_DIR}libwzd.lib"
  File "${LIBWZD-AUTH_RELEASE_DIR}libwzd_auth.lib"
  File "${LIBWZD-BASE_RELEASE_DIR}libwzd_base.lib"
  File "${LIBWZD_RELEASE_DIR}libwzd.lib"
  File "${MODULES_PERL_RELEASE_DIR}libwzd_perl.lib"
  File "${MODULES_SFV_RELEASE_DIR}libwzd_sfv.lib"
  File "${MODULES_TCL_RELEASE_DIR}libwzd_tcl.lib"
  File "${RELEASE_DIR}libwzd_core.lib"
SectionEnd

;--------------------------------
;Installer Functions

Function .onInit
  !insertmacro MUI_LANGDLL_DISPLAY
  Call GetWindowsFamily
  Pop $WindowsFamily
FunctionEnd

;--------------------------------
;Descriptions
  

  !insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${MainSec} $(DESC_MainSec)
  !insertmacro MUI_DESCRIPTION_TEXT ${TCLSec} $(DESC_TCLSec)
  !insertmacro MUI_DESCRIPTION_TEXT ${PerlSec} $(DESC_PerlSec)
  !insertmacro MUI_DESCRIPTION_TEXT ${MySQLSec} $(DESC_MySQLSec)
  !insertmacro MUI_DESCRIPTION_TEXT ${DevelopSec} $(DESC_DevelopSec)
  !insertmacro MUI_FUNCTION_DESCRIPTION_END

 
;--------------------------------
;Uninstaller Section

Section "Uninstall"
  ;Stops and unregister the service
  ExecWait '"$SYSDIR\net" stop wzdftpd' $0
  ExecWait '"$INSTDIR\wzdftpd.exe" -sd' $0

  RMDir /r "$SMPROGRAMS\wzdftpd\"
  RMDir /r "$INSTDIR\backends\"
  RMDir /r "$INSTDIR\tools\"
  RMDir /r "$INSTDIR\modules"
  RMDir /r "$INSTDIR\include"
  RMDir /r "$INSTDIR\lib"

  Delete "$INSTDIR\wzdftpd.pid"
  Delete "$INSTDIR\wzdftpd.exe"
  Delete "$INSTDIR\libwzd_core.dll"
  Delete "$INSTDIR\libwzd.dll"
  Delete "$INSTDIR\gnu_regex.dll"
  Delete "$INSTDIR\libiconv-2.dll"
  Delete "$INSTDIR\ssleay32.dll"
  Delete "$INSTDIR\libeay32.dll"
  Delete "$INSTDIR\zlib1.dll"
  Delete "$INSTDIR\AUTHORS"
  Delete "$INSTDIR\ChangeLog"
  Delete "$INSTDIR\COPYING"
  Delete "$INSTDIR\INSTALL"
  Delete "$INSTDIR\NEWS"
  Delete "$INSTDIR\Permissions.ReadMeFirst"
  Delete "$INSTDIR\README"
  Delete "$INSTDIR\TLS.ReadmeFirst"
  Delete "$INSTDIR\wzd_tls.cnf"
  Delete "$INSTDIR\wzd.pem"
  Delete "$INSTDIR\Uninstall.exe"
  Delete "$INSTDIR\${PROG_NAME}.url"

  DeleteRegKey /ifempty HKCU "Software\${PROG_NAME}"
  DeleteRegKey /ifempty ${PROG_UNINST_ROOT_KEY} "${PROG_UNINST_KEY}"
  SetAutoClose true
SectionEnd

;--------------------------------
;Uninstaller Functions

Function un.onInit
  !insertmacro MUI_UNGETLANGUAGE
FunctionEnd