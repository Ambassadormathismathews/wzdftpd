#include "wzd.h"

#define BUFFER_LEN	4096

void clientThreadProc(void *arg)
{
	char buffer[BUFFER_LEN];
	int sockfd;
	int ret;
	int msg_num;
	
	sockfd = *(int*)arg;
	
	out_log(LEVEL_INFO,"Client speaking to socket %d\n",sockfd);

	/* welcome msg */
	msg_num=220;
	snprintf(buffer,BUFFER_LEN,"%d %s\r\n",msg_num,getMessage(msg_num));
	ret = send(sockfd,buffer,strlen(buffer),0);

	/* login sequence */
	/** wait the USER john **/
	ret = recv(sockfd,buffer,BUFFER_LEN,0);
	/** reply 331 */
	msg_num=331;
	snprintf(buffer,BUFFER_LEN,"%d %s\r\n",msg_num,getMessage(msg_num));
	ret = send(sockfd,buffer,strlen(buffer),0);
	/** wait the PASS - XXX or AUTH TLS sequence **/
	ret = recv(sockfd,buffer,BUFFER_LEN,0);


	Sleep(2000);

	out_log(LEVEL_INFO,"Client dying (socket %d)\n",sockfd);
	close(sockfd);
}