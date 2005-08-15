# Microsoft Developer Studio Project File - Name="libwzd_auth" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=libwzd_auth - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "libwzd_auth.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "libwzd_auth.mak" CFG="libwzd_auth - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "libwzd_auth - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "libwzd_auth - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "libwzd_auth - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX- /O2 /I "../../" /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /YX /FD /c
# ADD BASE RSC /l 0x40c /d "NDEBUG"
# ADD RSC /l 0x40c /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ELSEIF  "$(CFG)" == "libwzd_auth - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /YX /FD /GZ /c
# ADD CPP /nologo /MTd /W3 /Gm /GX- /ZI /Od /I "../../" /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /YX /FD /GZ /c
# ADD BASE RSC /l 0x40c /d "_DEBUG"
# ADD RSC /l 0x40c /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ENDIF 

# Begin Target

# Name "libwzd_auth - Win32 Release"
# Name "libwzd_auth - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE="..\..\libwzd-auth\wzd_auth.c"
# End Source File
# Begin Source File

SOURCE="..\..\libwzd-auth\wzd_crypt.c"
# End Source File
# Begin Source File

SOURCE="..\..\libwzd-auth\wzd_md5.c"
# End Source File
# Begin Source File

SOURCE="..\..\libwzd-auth\wzd_md5crypt.c"
# End Source File
# Begin Source File

SOURCE="..\..\libwzd-auth\wzd_pam.c"
# End Source File
# Begin Source File

SOURCE="..\..\libwzd-auth\wzd_sha1.c"
# End Source File
# Begin Source File

SOURCE="..\..\libwzd-auth\wzd_sha1_hash.c"
# End Source File
# Begin Source File

SOURCE="..\..\libwzd-auth\wzd_tls.c"
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE="..\..\libwzd-auth\wzd_auth.h"
# End Source File
# Begin Source File

SOURCE="..\..\libwzd-auth\wzd_crypt.h"
# End Source File
# Begin Source File

SOURCE="..\..\libwzd-auth\wzd_md5.h"
# End Source File
# Begin Source File

SOURCE="..\..\libwzd-auth\wzd_md5crypt.h"
# End Source File
# Begin Source File

SOURCE="..\..\libwzd-auth\wzd_pam.h"
# End Source File
# Begin Source File

SOURCE="..\..\libwzd-auth\wzd_sha1.h"
# End Source File
# Begin Source File

SOURCE="..\..\libwzd-auth\wzd_tls.h"
# End Source File
# End Group
# End Target
# End Project
