#include "wzd.h"

wzd_config_t mainConfig;

int main(int argc, char **argv)
{
	int ret;

	ret = readConfigFile("wzd.cfg"); /* XXX */

	mainConfig.logfile = fopen(mainConfig.logfilename,mainConfig.logfilemode);

	ret = runMainThread(argc,argv);

	fclose(mainConfig.logfile);

	return ret;
}
