##for wzdftpd community
##simple .zip checker
##
##
##Put in wzd.cfg under 'cscript'
##cscript = POSTUPLOAD tcl:c:/wzdftpd/scripts/zip_check.tcl %username %usergroup {%filepath}
##
##
##set path to unzip.exe
set binary(UNZIP)  "./scripts/unzip.exe"
##
##
##main proc
proc zip_check {} {
  global binary wzd_args

  regsub -all -- {\"} $wzd_args {} wzd_args
  set user [lindex [split $wzd_args] 0]
  set group [lindex [split $wzd_args] 1]
  if {[string match -nocase *.zip [lindex $wzd_args 2]]} {
    catch {exec $binary(UNZIP) -qqt [lindex $wzd_args 2]} zipped
    if {$zipped != ""} {
      catch {file rename -force -- [lindex $wzd_args 2] [lindex $wzd_args 2].bad}
      send_message "+----------------------------------------------------"
      send_message "$user\($group\) uploaded BAD zip file '[file tail [lindex $wzd_args 2]]'."
      send_message "+----------------------------------------------------"
    } else {
      send_message "+----------------------------------------------------"
      send_message "$user\($group\) uploaded GOOD zip file '[file tail [lindex $wzd_args 2]]'."
      send_message "+----------------------------------------------------"
    }
  }
}

zip_check

