#
# wzdftpd - a modular and cool ftp server
# Copyright (C) 2002-2003  Pierre Chifflier
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
# As a special exemption, Pierre Chifflier
# and other respective copyright holders give permission to link this program
# with OpenSSL, and distribute the resulting executable, without including
# the source code for OpenSSL in the source distribution.
#
# wzdftpd script

set sitename	"WZD"

set wzd(srcdir) "/home/pollux/WORK/PROGS/wzd/wzdFTPd-configure/wzdftpd"
set wzd(log) "/usr/share/wzdftpd/logs/wzd.log"
set wzd(key)	0x44445555

# remember: path is relative to BOT CURRENT WORKING DIRECTORY
# (should be the one where you started the bot)
# in doubt, put absolute path
set file_help	"scripts/wzdftpd.help"

# DON'T REMOVE ANY MSGTYPES (RACE & DEFAULT) !!!
set msgtypes(RACE)	"IMDB ALLOCINE NFOURL NFO NEWDATE WIPE NEWDIR DELDIR INCOMPLETE NUKE UNNUKE PRE RACE SFV UPDATE HALFWAY NEWLEADER COMPLETE STATS"
set msgtypes(DEFAULT)	"INVITE LOGIN LOGOUT REQUEST REQFILLED REQDEL GIVE TAKE"


#########################################################
# setup each path you need like this
#
# set paths(section)	"/section/*" (vfs format)
# set type(section)		"RACE"
# set chanlist(section)	"#channel"
######################################################### 

set sections		"APPS DIVX MP3 0DAY REQUEST"
set defaultsection	"DEFAULT"

set paths(APPS)		"/apps/*"
set type(APPS)		"RACE"
set chanlist(APPS)	"#wzdftpd-pv"

set paths(DIVX)		"/divx/*"
set type(DIVX)		"RACE"
set chanlist(DIVX)	"#wzdftpd-pv"

set paths(MP3)		"/mp3/*"
set type(MP3)		"RACE"
set chanlist(MP3)	"#wzdftpd-pv"

set paths(REQUEST)	"/request/*"
set type(REQUEST)	"RACE"
set chanlist(REQUEST)	"#wzdftpd-pv"

set paths(0DAY)		"/0day/*"
set type(0DAY)		"RACE"
set chanlist(0DAY)	"#wzdftpd-pv"

#########################################################

set chanlist(ALL)	"#wzdftpd"
set chanlist(DEFAULT)	"#wzdftpd-pv"
set chanlist(DF)	"#wzdftpd"
set chanlist(INVITE)	"#wzdftpd-pv"
set chanlist(WELCOME)	"#wzdftpd-pv"

set chanlist(COMPLETE)	"#wzdftpd-pv"

set binary(DF)		"/bin/df"
set binary(NCFTPLS)	"/usr/bin/ncftpls"
set binary(UPTIME)	"/usr/local/bin/siteuptime"
set binary(WHO)		"/usr/local/bin/sitewho"

set cmdpre         	"!wzd"



#set bnc(LIST)		"127.0.0.1:6969 127.0.0.1:10000 127.0.0.1:10001"
set bnc(LIST)		"127.0.0.1:21"
set bnc(USER)		"anonymous"
set bnc(PASS)		"pass"
set bnc(TIMEOUT)	"3"


# example for windows
#set device(0)           "C: hd-c"
#set device(1)           "D: hd-d"

set device(0)		"/dev/hda1 root"
set device(1)		"/dev/hda3 usr"
set device(2)		"/dev/hda4 home"
set device(3)		"134.214.50.12:/bigdisk/pollux linux5"
set device(TOTAL)	4



# MSGTYPES: ENABLE=0/DISABLE=1 ANNOUNCES
set disable(DEFAULT)		0

set disable(BNCTEST)		0
set disable(FREE)		0
set disable(UPTIME)		0
set disable(WELCOME)		0

set disable(NEWDIR)		0
set disable(DELDIR)		0
set disable(COMPLETE)		0
set disable(WIPE)		0
set disable(PRE)		0
set disable(INVITE)		0
set disable(NUKE)		0
set disable(UNNUKE)		0
set disable(LOGIN)		1
set disable(LOGOUT)		1
set disable(NEWDATE)		0
set disable(REQUEST)		0
set disable(REQFILLED)		0
set disable(REQDEL)		0
set disable(INCOMPLETE)		0
set disable(IMDB)		0
set disable(ALLOCINE)		0
set disable(NFOURL)		0
set disable(NFO)		0
set disable(GIVE)		0
set disable(TAKE)		0




set hlp "help"
set announce(WELCOME)		"Welcome to $sitename channel. Type $cmdpre$hlp for help."
set announce(DF)		"-%sitename- \[%section\] + %msg"


#########################################################
# ADVANCED CONFIG, EDIT _VERY_ CAREFULLY                #
#########################################################

# !!! denypost is CASE SENSITIVE !!!
set denypost "*COMPLETE* *NUKED* *IMDB*"
set hidenuke "UNKNOWN"
set mpath ""

## Splits output line to smaller pieces
# 
# To disable set it to "\n"

set splitter(CHAR) "|"

## Defining variables for announce
#
# Example:
#  set variables(PRE) "%pf %user %group %pregroup %files %mbytes"
#  set announce(PRE)  "-%sitename- \[%section\] %user@%group launches new %pregroup-pre called %release (%mbytesM in %filesF)"
#
# Special variables: 
#  %pf      = path filter, must be the first parameter and contain full path of the release, it defines:
#   %release = Last directory in path ( /site/xxx/marissa-exxtasy/cd1 => cd1 )
#   %path    = Second last directory in path ( /site/xxx/marissa-exxtasy/cd1 => marissa-exxtasy )
#   %relname = all directories after those defined in paths 
#              ( paths(ISO) = "/site/xxx/" does: /site/xxx/marissa-exxtasy/cd1 => marissa-exxtasy/cd1 ) 
#

# !!!! MODIFY _VERY_ CAREFULLY  ANY VARIABLES BELOW !!!!
# !!!! MODIFY _VERY_ CAREFULLY  ANY VARIABLES BELOW !!!!
# !!! IF YOU DON'T KNOW WHAT CHANGE !!! DON'T CHANGE !!!

set variables(NEWDIR)		"%pf %user %group"
set variables(DELDIR)		"%pf %user %group"
set variables(COMPLETE)		"%pf %user %group %tagline"
set variables(LOGIN)		"%no %user %group %tagline"
set variables(LOGOUT)		"%no %user %group %tagline"
set variables(INVITE)		"%user %group %ircnick"
set variables(WIPE)		"%pf %user %group %dirs %files %size"
set variables(PRE)		"%pf %user %group %files %mbytes"
set variables(REQUEST)		"%user %group %request"
set variables(REQFILLED)	"%user %group %request"
set variables(REQDEL)		"%user %group %request"
set variables(NEWDATE)		"%pf"
set variables(IMDB)		"%pf %url %title %name %genre %plot %rating %bar %time %budget %screens %user %group"
set variables(ALLOCINE)		"%pf %url %user %group"
set variables(NFOURL)		"%pf %url %user %group"
set variables(NFO)		"%pf %no %user %group"
set variables(GIVE)		"%user %group %mb %target"
set variables(TAKE)		"%user %group %mb %target"

set variables(DEFAULT)		"%pf %msg"

## RANDOMIZING OUTPUT
#
# Example:
#  set random(NEWDIR-0)       "-%sitename- \[%section\] + %user@%group creates a directory called %release"
#  set random(NEWDIR-1)       "-%sitename- \[%section\] + %user@%group makes a directory called %release"
#  set random(NEWDIR-2)       "-%sitename- \[%section\] + %user@%group does mkdir %release"
#   TYPE --------^   ^
#         ID --------^              
#
#  set announce(NEWDIR) "random 3"
#   TYPE ---------^        ^    ^
#         RANDOM ----------^    ^
#             # OF IDS ---------^

set announce(NEWDIR)		"-%sitename- \[%section\] + New Release: %path/%bold%release%bold (%relname) by %bold%user%bold@%group"
set announce(DELDIR)		"-%sitename- \[%section\] + Directory deleted: %path/%bold%release%bold by %bold%user%bold@%group"
set announce(COMPLETE)		"-%sitename- \[%section\] + %path/%bold%release%bold (%relname) was completed by %bold%user%bold@%group"
set announce(BW)			"-%sitename-  \[%section\] + Uploaders: %uploaders@%bold%upspeed%boldkb/sec - Leechers: %leechers@%bold%dnspeed%boldkb/sec - Idlers: %bold%idlers%bold - Total: %totalusers@%bold%totalspeed%boldkb/sec"
set announce(LOGIN)			"-%sitename- \[LOGIN\] + %bold%user%bold@%group has logged in"
set announce(LOGOUT)		"-%sitename- \[LOGOUT\] + %bold%user%bold@%group has logged out"
set announce(NUKE)			"-%sitename- \[%section\] + %path/%bold%release%bold was %ulinenuked %mult%ulinex by %bold%nuker%bold - reason: %reason - nukees: %nukees"
set announce(UNNUKE)		"-%sitename- \[%section\] + %path/%bold%release%bold was %ulineunnuked %mult%ulinex by %bold%nuker%bold - reason: %bold%reason%bold - returned: %nukees"
set announce(INVITE)		"-%sitename- \[INVITE\] + %bold%user%bold@%group invited himself as %bold%ircnick%bold"
set announce(MSGINVITE)		"-%sitename- \[INVITE\] + %bold%user%bold@%group invited himself as %bold%ircnick%bold"
set announce(BADMSGINVITE)	"-%sitename- \[INTRUDER\] + %bold%ircnick%bold (%host) tried to invite himself with invalid login!"
set announce(WIPE)			"-%sitename- \[%section\] + %bold%user%bold@%group wiped %path/%bold%release%bold %sizeMB (%bold%files%bold files, %bold%dirs%bold dirs)"
set announce(NEWDATE)		"-%sitename- \[%section\] + That's it! New day has come, change your current %bold%path%bold dir to %bold%release%bold"
set announce(PRE)			"-%sitename- \[%section\] + %bold%user%bold launches new %bold%group-PRE%bold called %release (%bold%mbytes%boldM in %bold%files%boldF) in %bold%path%bold"
set announce(REQUEST)		"-%sitename- \[REQUEST\] + %bold%request%bold added by %bold%user%bold@%group"
set announce(REQFILLED)		"-%sitename- \[REQFILLED\] + %bold%request%bold filled by %bold%user%bold@%group"
set announce(REQDEL)		"-%sitename- \[REQDEL\] + %bold%request%bold deleted by %bold%user%bold@%group"
#set announce(IMDB)			"-%sitename- \[%section\] + Recieved info for %bold%title%bold -> rated %uline%rating%uline - genre: %genre - runtime: %time >> URL: %uline%url%uline >> Screens: %screens"
set announce(IMDB)			"-%sitename- \[%section\] + Recieved info for %bold%title%bold \n >> Directed by: %bold%name%bold \n >> Rating: %bold%rating%bold %bar \n >> Genre: %bold%genre%bold \n >> Runtime: %bold%time%bold \n >> %boldURL:%bold %uline%url%uline \n >> %boldPlot Outline:%bold %plot \n >> Extra infos: %boldBudget:%bold %budget -> %boldScreens:%bold %screens"
set announce(ALLOCINE)		"-%sitename- \[%section\] + Recieved info for %bold%path%bold URL: %uline%url%uline"
set announce(NFOURL)		"-%sitename- \[%section\] + Recieved info for %bold%path%bold URL: %uline%url%uline"
set announce(NFO)			"-%sitename- \[%section\] + %bold%user%bold@%group found a flyer for %bold%path%bold, called %bold%release%bold"
set announce(GIVE)			"-%sitename- \[GIVE\] + Hey!! %bold%target%bold you are a lucky guy. %bold%user%bold@%group GIVE you %bold%mb%boldMB"
set announce(TAKE)			"-%sitename- \[TAKE\] + Hey!! %bold%target%bold what's wrong with you? %bold%user%bold@%group TAKE you %bold%mb%boldMB"

## NO RANDOMIZING OUTPUT with announces below
## IF YOU DON'T KNOW WHAT TO CHANGE !!! DON'T TOUCH !!!
set announce(REQHEADER)		"-%sitename- -----\[ Current Requests \]"
set announce(REQUESTSHOW)	"-%sitename- \[%cnt\] - %bold%user%bold is looking for %bold%request%bold"
set announce(REQFOOT)		"-%sitename- -----\[ End \]"
set announce(UPLOAD)		"-%sitename- \[%section\] + %bold%user%bold@%group is uploading %file @ %bold%speed%boldkb/sec"
set announce(LEECH)			"-%sitename- \[%section\] + %bold%user%bold@%group is downloading %file @ %bold%speed%boldkb/sec"
set announce(IDLE)			"-%sitename- \[%section\] + %bold%user%bold@%group done %bold%action%bold since %time secs"
set announce(SPEED)			"-%sitename- \[%section\] + %bold%user%bold@%group %action %file @%speedkb/sec"

set announce(NOUPLOAD)		"-%sitename- \[%section\] + Ohh Noo !! Give us something to trade !!"
set announce(NOLEECH)		"-%sitename- \[%section\] + Ohh Yeah !! We are free from Leechers !!"
set announce(NOIDLE)		"-%sitename- \[%section\] + Yeah Good !! no fucking Idlers online !!"
set announce(NOSPEED)		"-%sitename- \[%section\] + %msg"

set hlp "help"
set announce(WELCOME)		"Welcome to this site channel. Type $cmdpre$hlp for help."
set announce(DEFAULT)		"-%sitename- \[%section\] + %msg"



putlog "Loading wzdftpd"

proc say {who what} {
	puthelp "PRIVMSG $who :$what"
}
proc notice {who what} {
	puthelp "NOTICE $who :$what"
}

#################################################################################
# SET BINDINGS                                                                  #
#################################################################################

bind pub -|- [set cmdpre]news wzd:news
bind pub -|- [set cmdpre]bnc wzd:bnc
bind pub -|- [set cmdpre]chan_who wzd:chan_who
bind pub -|- [set cmdpre]free wzd:show_free
bind pub -|- [set cmdpre]help wzd:help
bind pub -|- [set cmdpre]uptime wzd:uptime
bind pub -|- [set cmdpre]who wzd:who

bind join -|- * wzd:welcome_msg

#################################################################################
# SEND TO ALL CHANNELS LISTED                                                   #
#################################################################################
proc wzd:sndall {section args} {
 global chanlist splitter
 foreach chan $chanlist($section) {
  foreach line [split [lindex $args 0] $splitter(CHAR)] {
   putquick "PRIVMSG $chan :$line"
  }
 }
}



#################################################################################
# GET SECTION NAME (BASED ON PATH)                                              #
#################################################################################
proc wzd:getsection {cpath msgtype} {
  global sections msgtypes paths type defaultsection mpath
  foreach section $sections {
    foreach path $paths($section) {
      if { [string match $path $cpath] == 1 && [string first $msgtype $msgtypes($type($section))] != -1 } {
	set mpath $path
	return $section
      }
    }
  }
  return $defaultsection
}




#################################################################################
# REPLACE WHAT WITH WITHWHAT                                                    #
#################################################################################
proc wzd:replacevar {strin what withwhat} {
  global zeroconvert
  set output $strin
  set replacement $withwhat
  if { [string length $replacement] == 0 && [info exists zeroconvert($what)] } { set replacement $zeroconvert($what) }
  set cutpos 0
  while { [string first $what $output] != -1 } {
    set cutstart [expr [string first $what $output] - 1]
    set cutstop  [expr $cutstart + [string length $what] + 1]
    set output [string range $output 0 $cutstart]$replacement[string range $output $cutstop end]
  }
  return $output
}


#################################################################################
# CONVERT BASIC COOKIES TO DATA                                                 #
#################################################################################
proc wzd:basicreplace {strin section} {
  global sitename
  set output [wzd:replacevar $strin "%sitename" $sitename]
  set output [wzd:replacevar $output "%bold" "\002"]
  set output [wzd:replacevar $output "%color" "\003"]
  set output [wzd:replacevar $output "%uline" "\037"]
  set output [wzd:replacevar $output "%section" $section]
  return "$output"
}



#################################################################################
# CONVERT COOKIES TO DATA                                                       #
#################################################################################
proc wzd:parse {msgtype msgline section} {
#  putlog "$msgtype $msgline $section"
  global variables announce random mpath
  set type $msgtype
  if { ! [string compare $type "NUKE"] || ! [string compare $type "UNNUKE"] } {
    wzd:fuelnuke $type [lindex $msgline 0] $section $msgline
    return ""
  }
  if { ! [info exists announce($type)] || ! [info exists variables($type)] } { set type "DEFAULT" }
  set vars $variables($type)
  if { ! [string compare [lindex $announce($type) 0] "random"] && [string is alnum -strict [lindex $announce($type) 1]] == 1 } {
    set output $random($msgtype\-[rand [lindex $announce($type) 1]])
  } else {
    set output $announce($type)
  }
  set output [wzd:basicreplace $output $section]
  set cnt 0
  if { [ string compare [lindex $vars 0] "%pf" ] == 0 } {
    set split [split [lindex $msgline 0] "/"]
    set ll [llength $split]
    set split2 [split $mpath "/"]
    set sl [llength $split2]
    set temp [lrange $split [expr $sl - 1] end]
    set relname ""
    foreach part $temp {
      set relname $relname/$part
    }
    set temp [string range $relname 1 end]
    set output [wzd:replacevar $output "%relname" $temp]
    set output [wzd:replacevar $output "%release" [lindex $split [expr $ll -1]]]
    set output [wzd:replacevar $output "%path" [lindex $split [expr $ll -2]]]
    set vars [string range $vars 4 end]
    set cnt 1
  }
  foreach vari $vars {
    set output [wzd:replacevar $output $vari [lindex $msgline $cnt]]
    set cnt [expr $cnt + 1]
  }
  return $output
}




#################################################################################
# CHECK IF RELEASE SHOULD NOT BE ANNOUNCED                                      #
#################################################################################
proc wzd:denycheck {strin} {
  global denypost
  foreach deny $denypost {
    if { [string match $deny $strin] == 1 } { return 1 }
  }
  return 0
}


#################################################################################
# POST WHO INFO                                                                 #
#################################################################################
proc wzd:who {nick uhost hand chan args} {
  global binary wzd
  foreach line [split [exec $binary(WHO) -k $wzd(key)] \n] {
    if { ! [info exists newline($line)] } { set newline($line) 0 } else { set newline($line) [expr $newline($line) + 1] }
    puthelp "PRIVMSG $nick :$line\003$newline($line)"
  }
}          



#################################################################################
# POST UPTIME INFO                                                              #
#################################################################################
proc wzd:uptime {nick uhost hand chan args} {
  global binary wzd
  foreach line [split [exec $binary(UPTIME) -k $wzd(key)] \n] {
    if { ! [info exists newline($line)] } { set newline($line) 0 } else { set newline($line) [expr $newline($line) + 1] }
    puthelp "PRIVMSG $nick :$line\003$newline($line)"
  }
}          




#################################################################################
# POST WHO INFO ON CHAN                                                         #
#################################################################################
proc wzd:chan_who {nick uhost hand chan args} {
  global binary wzd
  foreach line [split [exec $binary(WHO) -k $wzd(key)] \n] {
    if { ! [info exists newline($line)] } { set newline($line) 0 } else { set newline($line) [expr $newline($line) + 1] }
    puthelp "PRIVMSG $chan :$line\003$newline($line)"
  }
}          



#################################################################################
# SHOW WELCOME MSG                                                              #
#################################################################################
proc wzd:welcome_msg { nick uhost hand chan } {
  global announce disable chanlist
  if { $disable(WELCOME) == 0 } {
    foreach c_chan $chanlist(WELCOME) {
      if { [string match -nocase $c_chan $chan] == 1 } {
	puthelp "NOTICE $nick : $announce(WELCOME)"
      }
    }
  }
}


#################################################################################
#                                  Help Section                                 #
#################################################################################
proc wzd:help {nick uhost hand chan arg} {
  global sections cmdpre file_help
  if {![file exist $file_help]} {
    puthelp "PRIVMSG $nick : help file $file_help is missing please check install"
    return 0
  }
  puthelp "PRIVMSG $nick : -------== W Z D ==--------"
  puthelp "PRIVMSG $nick : - wzdFTPd's sitebot help -"
  puthelp "PRIVMSG $nick : ---------=== ===----------"
  puthelp "PRIVMSG $nick : "
  puthelp "PRIVMSG $nick : All comands begin with $cmdpre"
  set htopic [lindex $arg 0]
  if {$htopic == ""} {
    set helpfile [open $file_help r]
    set helpdb [read $helpfile]
    close $helpfile
    foreach line [split $helpdb "\n"] {
      puthelp "PRIVMSG $nick :$line"
    }
    puthelp "PRIVMSG $nick : Valid sections are : $sections"
  }
  if {$htopic != ""} {
    set hlpd "0"
    set helpfile [open $file_help r]
    set helpdb [read $helpfile]
    close $helpfile
    foreach line [split $helpdb "\n"] {
      if {[lindex $line 0] == "$htopic"} {
        puthelp "PRIVMSG $nick :$line"
        set hlpd "1"
      }
    }
    if {$hlpd == "0"} { 
      puthelp "PRIVMSG $nick : no help on that"
    }
  }
}



#################################################################################
# SHOW BNC LIST                                                                 #
#################################################################################
proc wzd:bnc { nick uhost hand chan arg } {
  global bnc sitename binary disable
  if { $disable(BNCTEST) == 1 } {
    putlog "BNC disabled"
      putquick "NOTICE $nick :BNC disabled"
      return 0
  }
  putquick "NOTICE $nick : list of bnc's for $sitename"
  foreach eachbnc $bnc(LIST) {
    if {$eachbnc == ""} {continue}
    set status  [catch { exec $binary(NCFTPLS) -u$bnc(USER) -p$bnc(PASS) -t$bnc(TIMEOUT) ftp://$eachbnc } result]
    if { $status == 0 } { set bncchk "UP" } else { set bncchk "DOWN" }
    puthelp "NOTICE $nick : $eachbnc - $bncchk"
  }
}



#################################################################################
# SHOW FREE SPACE                                                               #
#################################################################################
proc wzd:show_free { nick uhost hand chan arg } {
  global binary announce device disable
  if { $disable(FREE) == 1 } {
    putlog "FREE disabled"
      putquick "NOTICE $nick :FREE disabled"
      return 0
  }
  set output $announce(DF)
  for {set i 0} {$i < $device(TOTAL)} {incr i} {
    foreach line [split [exec $binary(DF) "-P" "-m"] "\n"] {
      if { [string match [lindex $line 0] [string tolower [lindex $device($i) 0]]] == 1 } {
	append devices "\[[lindex $device($i) 1]: %bold[format %.2f [expr [lindex $line 3].0/1024]]%bold/[format %.2f [expr [lindex $line 1].0/1024]]GB\] - "
      }
    }
  }
  set output [wzd:replacevar $output "%msg" $devices]
  set output [wzd:basicreplace $output "FREE"]
#   wzd:sndall "DF" $output
  say $chan $output
}




#################################################################################
# ANNOUNCE LATEST NEWS FROM CHANGELOG                                           #
#################################################################################
proc wzd:news { nick host hand chan arg } {
  global wzd
  set file $wzd(srcdir)
  set channel [open "$file/ChangeLog" r]
  set data [split [read $channel] "\n"]
  close $channel
  set lineid 0
  foreach line $data {
    if {$line == ""} {continue}
    incr lineid
    if {$lineid != 1} {
      if {[string is digit [string range $line 0 0]]} {break}
    }
#    wzd:sndall ALL  $line
    say $chan $line
  }
}



set lastoct [file size $wzd(log)]

#################################################################################
# MAIN LOOP - PARSES DATA FROM wzd.log                                          #
#################################################################################
proc wzd_readlog {} {
  global wzd lastoct defaultsection disable variables msgtypes chanlist

  utimer 1 "wzd_readlog"

  set wzdftpdlogsize [file size $wzd(log)]
  if { $wzdftpdlogsize == $lastoct } { return 0 }
  if { $wzdftpdlogsize  < $lastoct } { set lastoct 0 }
  if { [catch { set of [open $wzd(log) r] } ] } { return 0 }

  seek $of $lastoct
  while {![eof $of]} {
    set line [gets $of]
    if {$line == ""} {continue}
    set msgtype [string trim [lindex $line 5] ":"]
    if { ! [info exists disable($msgtype)] || $disable($msgtype) == 1 } {
#      putlog "$msgtype close of return 0"
      close $of
      set lastoct [file size $wzd(log)]
      return 0
    }
    if { $msgtype == "NEWDIR" || $msgtype == "DELDIR" || $msgtype == "COMPLETE" } {
      set path [lindex $line 6]
      if { $msgtype == "DELDIR" } { set path [string trimright $path "/"] }
      set var1 "{$path} [lrange $line 7 8]"
#    } elseif { $msgtype == "IMDB" } {
#      set path [lindex $line 3]
#	set var1 [imdbcall $path [lindex $line 4] [lindex $line 5] [lindex $line 6] [lindex $line 7]]
    } else {
      set path [lindex $line 7]
      set var1 [lrange $line 7 end]
    }
    if { ! [string compare $msgtype "INVITE"] } {
      set nick [lindex $line 9]
      foreach channel $chanlist(INVITE) {
	puthelp "INVITE $nick $channel"
      }
    }
#    say $chanlist(DEFAULT) "prout $path $msgtype"
    set section [wzd:getsection $path $msgtype]
#    set section "DEFAULT"
    if { [wzd:denycheck "$path"] == 0 } {
      if { [string compare "$section" "$defaultsection"] } {
	if { $disable($msgtype) == 0 || $disable(DEFAULT) == 0 } {
	  if { [info exists variables($msgtype)] } {
	    set echoline [wzd:parse $msgtype $var1 $section]
	      wzd:sndall $section $echoline
	  } else {
	    set echoline [wzd:parse DEFAULT $var1 $section]
	      wzd:sndall $section $echoline
	  }
	}
      } else {
	if { [lsearch -glob $msgtypes(DEFAULT) $msgtype] != -1 } {
	  if { $disable($msgtype) == 0 } {
	    set echoline [wzd:parse $msgtype $var1 "DEFAULT"]
	      wzd:sndall "DEFAULT" $echoline
	  }
	} else { 
	  if { $disable(DEFAULT) == 0 } {
	    set echoline [wzd:parse $msgtype $var1 "DEFAULT"]
	      wzd:sndall "DEFAULT" $echoline
	  }
	}
      }
    }

#    say $chanlist(DEFAULT) $line
  }
  close $of
  set lastoct [file size $wzd(log)]
  return 0
}

wzd_readlog
putlog "wzdftpd 0.1 loaded !"
