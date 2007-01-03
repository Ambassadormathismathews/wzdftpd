# order is important
prefix="@CMAKE_INSTALL_PREFIX@"
exec_prefix="${prefix}"
exec_prefix_set="no"
datarootdir="${prefix}/share"
data_dir="${datarootdir}/@PACKAGE@"

version="@WZD_VERSION@"
includedir="${prefix}/include"
wzd_include_dir="${prefix}/include/@PACKAGE@"
lib_dir="${exec_prefix}/lib"

Name: @PACKAGE@
Description: A portable, modular, small and efficient ftp server
Version: @WZD_VERSION@
Requires:
Libs: -lwzd-core @PTHREAD_CFLAGS@ @PTHREAD_LIBS@ @WZD_SSL_LIBS@
Cflags: -I${wzd_include_dir} @PTHREAD_CFLAGS@ @WZD_SSL_INCLUDES@
