# Microsoft Developer Studio Project File - Name="libwzd_core" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=libwzd_core - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "libwzd_core.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "libwzd_core.mak" CFG="libwzd_core - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "libwzd_core - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "libwzd_core - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "libwzd_core - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "LIBWZD_EXPORTS" /Yu"stdafx.h" /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /D "WZD_USE_PCH" /D "NDEBUG" /D "WZD_MULTITHREAD" /D "HAVE_OPENSSL" /D "HAVE_UTF8" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "LIBWZD_EXPORTS" /Yu"wzd_all.h" /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x40c /d "NDEBUG"
# ADD RSC /l 0x40c /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib wsock32.lib /nologo /dll /machine:I386 /def:"libwzd_core.def"
# SUBTRACT LINK32 /pdb:none /debug

!ELSEIF  "$(CFG)" == "libwzd_core - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "LIBWZD_EXPORTS" /Yu"stdafx.h" /FD /GZ /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WZD_USE_PCH" /D "DEBUG" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "LIBWZD_EXPORTS" /Yu"wzd_all.h" /FD /GZ /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x40c /d "_DEBUG"
# ADD RSC /l 0x40c /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib wsock32.lib /nologo /dll /debug /machine:I386 /def:"libwzd_core.def" /pdbtype:sept
# SUBTRACT LINK32 /pdb:none

!ENDIF 

# Begin Target

# Name "libwzd_core - Win32 Release"
# Name "libwzd_core - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=..\src\inet_ntop.c
# End Source File
# Begin Source File

SOURCE=..\src\inet_pton.c
# End Source File
# Begin Source File

SOURCE=.\libwzd_core.def
# End Source File
# Begin Source File

SOURCE=..\src\list.c
# End Source File
# Begin Source File

SOURCE=..\src\wzd_action.c
# End Source File
# Begin Source File

SOURCE=..\src\wzd_all.c
# ADD CPP /Yc"wzd_all.h"
# End Source File
# Begin Source File

SOURCE=..\src\wzd_backend.c
# End Source File
# Begin Source File

SOURCE=..\src\wzd_cache.c
# End Source File
# Begin Source File

SOURCE=..\src\wzd_cookie_lex.c
# SUBTRACT CPP /YX /Yc /Yu
# End Source File
# Begin Source File

SOURCE=..\src\wzd_cookie_lex.l

!IF  "$(CFG)" == "libwzd_core - Win32 Release"

# Begin Custom Build
InputDir=\HOMEDIR\wzdftpd\src
InputPath=..\src\wzd_cookie_lex.l
InputName=wzd_cookie_lex

"$(InputDir)\$(InputName).c" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	.\flex\Release\flex.exe -t $(InputDir)\$(InputName).l > $(InputDir)\$(InputName).c

# End Custom Build

!ELSEIF  "$(CFG)" == "libwzd_core - Win32 Debug"

# Begin Custom Build
InputDir=\HOMEDIR\wzdftpd\src
InputPath=..\src\wzd_cookie_lex.l
InputName=wzd_cookie_lex

"$(InputDir)\$(InputName).c" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	.\flex\Release\flex.exe -t $(InputDir)\$(InputName).l > $(InputDir)\$(InputName).c

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\src\wzd_crc32.c
# End Source File
# Begin Source File

SOURCE=..\src\wzd_crontab.c
# End Source File
# Begin Source File

SOURCE=..\src\wzd_crypt.c
# SUBTRACT CPP /YX /Yc /Yu
# End Source File
# Begin Source File

SOURCE=..\src\wzd_debug.c
# End Source File
# Begin Source File

SOURCE=..\src\wzd_dir.c
# End Source File
# Begin Source File

SOURCE=..\src\wzd_file.c
# End Source File
# Begin Source File

SOURCE=..\src\wzd_ip.c
# End Source File
# Begin Source File

SOURCE=..\src\wzd_libmain.c
# End Source File
# Begin Source File

SOURCE=..\src\wzd_log.c
# End Source File
# Begin Source File

SOURCE=..\src\wzd_md5.c
# End Source File
# Begin Source File

SOURCE=..\src\wzd_md5crypt.c
# SUBTRACT CPP /YX /Yc /Yu
# End Source File
# Begin Source File

SOURCE=..\src\wzd_messages.c
# End Source File
# Begin Source File

SOURCE=..\src\wzd_misc.c
# End Source File
# Begin Source File

SOURCE=..\src\wzd_mod.c
# End Source File
# Begin Source File

SOURCE=..\src\wzd_mutex.c
# End Source File
# Begin Source File

SOURCE=..\src\wzd_perm.c
# End Source File
# Begin Source File

SOURCE=..\src\wzd_section.c
# End Source File
# Begin Source File

SOURCE=..\src\wzd_shm.c
# End Source File
# Begin Source File

SOURCE=..\src\wzd_strlcat.c
# End Source File
# Begin Source File

SOURCE=..\src\wzd_strptime.c
# End Source File
# Begin Source File

SOURCE=..\src\wzd_strtok_r.c
# End Source File
# Begin Source File

SOURCE=..\src\wzd_strtoull.c
# End Source File
# Begin Source File

SOURCE=..\src\wzd_utf8.c
# End Source File
# Begin Source File

SOURCE=..\src\wzd_vars.c
# End Source File
# Begin Source File

SOURCE=..\src\wzd_vfs.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=..\src\list.h
# End Source File
# Begin Source File

SOURCE=..\src\wzd_action.h
# End Source File
# Begin Source File

SOURCE=..\src\wzd_all.h
# End Source File
# Begin Source File

SOURCE=..\src\wzd_backend.h
# End Source File
# Begin Source File

SOURCE=..\src\wzd_cache.h
# End Source File
# Begin Source File

SOURCE=..\src\wzd_crc32.h
# End Source File
# Begin Source File

SOURCE=..\src\wzd_crontab.h
# End Source File
# Begin Source File

SOURCE=..\src\wzd_crypt.h
# End Source File
# Begin Source File

SOURCE=..\src\wzd_debug.h
# End Source File
# Begin Source File

SOURCE=..\src\wzd_dir.h
# End Source File
# Begin Source File

SOURCE=..\src\wzd_file.h
# End Source File
# Begin Source File

SOURCE=..\src\wzd_hardlimits.h
# End Source File
# Begin Source File

SOURCE=..\src\wzd_ip.h
# End Source File
# Begin Source File

SOURCE=..\src\wzd_libmain.h
# End Source File
# Begin Source File

SOURCE=..\src\wzd_log.h
# End Source File
# Begin Source File

SOURCE=..\src\wzd_md5.h
# End Source File
# Begin Source File

SOURCE=..\src\wzd_md5crypt.h
# End Source File
# Begin Source File

SOURCE=..\src\wzd_messages.h
# End Source File
# Begin Source File

SOURCE=..\src\wzd_misc.h
# End Source File
# Begin Source File

SOURCE=..\src\wzd_mod.h
# End Source File
# Begin Source File

SOURCE=..\src\wzd_mutex.h
# End Source File
# Begin Source File

SOURCE=..\src\wzd_perm.h
# End Source File
# Begin Source File

SOURCE=..\src\wzd_section.h
# End Source File
# Begin Source File

SOURCE=..\src\wzd_shm.h
# End Source File
# Begin Source File

SOURCE=..\src\wzd_strlcat.h
# End Source File
# Begin Source File

SOURCE=..\src\wzd_strptime.h
# End Source File
# Begin Source File

SOURCE=..\src\wzd_strtok_r.h
# End Source File
# Begin Source File

SOURCE=..\src\wzd_strtoull.h
# End Source File
# Begin Source File

SOURCE=..\src\wzd_structs.h
# End Source File
# Begin Source File

SOURCE=..\src\wzd_types.h
# End Source File
# Begin Source File

SOURCE=..\src\wzd_utf8.h
# End Source File
# Begin Source File

SOURCE=..\src\wzd_vars.h
# End Source File
# Begin Source File

SOURCE=..\src\wzd_vfs.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# Begin Source File

SOURCE=.\ReadMe.txt
# End Source File
# Begin Source File

SOURCE=.\gnu_regex_dist\gnu_regex.lib
# End Source File
# End Target
# End Project
