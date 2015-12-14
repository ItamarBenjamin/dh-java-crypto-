// g++ -g3 -ggdb -O0 -I. -I/usr/include/cryptopp dh-agree.cpp -o dh-agree.exe -lcryptopp -lpthread
// g++ -g -O2 -I. -I/usr/include/cryptopp dh-agree.cpp -o dh-agree.exe -lcryptopp -lpthread

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <string>
using std::string;

#include <stdexcept>
using std::runtime_error;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "integer.h"
using CryptoPP::Integer;

#include "nbtheory.h"
using CryptoPP::ModularExponentiation;

#include "dh.h"
using CryptoPP::DH;

#include "secblock.h"
using CryptoPP::SecByteBlock;

#include <hex.h>
using CryptoPP::HexEncoder;

#include <filters.h>
using CryptoPP::StringSink;

int sendData(byte* data, int len)
{
    int sockfd = 0, n = 0;
    struct sockaddr_in serv_addr; 

    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Error : Could not create socket \n");
        return 1;
    } 

    memset(&serv_addr, '0', sizeof(serv_addr)); 

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(5454); 

    if(inet_pton(AF_INET, "127.0.0.1" , &serv_addr.sin_addr)<=0)
    {
        printf("\n inet_pton error occured\n");
        return 1;
    } 

    if( connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
       printf("\n Error : Connect Failed \n");
       return 1;
    } 

	int sent = 0;
    while ( sent < len)
    {
		n = write(sockfd, data + sent, len-sent);
		if ( n == -1)
		{
			printf("Error writing. %d\n",errno);
			return 1;
		}
		sent += n;
		printf("sent %d bytes, remaining %d\n",n,len - sent);
    }
	close(sockfd); 

    return 0;
}

int readData(byte* data, int len)
{
	int listenfd = 0, connfd = 0;
    struct sockaddr_in serv_addr; 

    time_t ticks; 

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&serv_addr, '0', sizeof(serv_addr));
    memset(data, '0', sizeof(data)); 

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(5455); 

    bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)); 

    listen(listenfd, 10); 

    connfd = accept(listenfd, (struct sockaddr*)NULL, NULL); 
	int n = 0, count = 0;
	do
	{
		n += count;
    	count = read(connfd, data + n, 100); 
	} while (count > 0);

    close(connfd);
	return n;
}

int main(int argc, char** argv)
{
	try
	{
		// RFC 5114, 1024-bit MODP Group with 160-bit Prime Order Subgroup
		// http://tools.ietf.org/html/rfc5114#section-2.1
		Integer p("0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
			"9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
			"13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
			"98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
			"A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
			"DF1FB2BC2E4A4371");

		Integer g("0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
			"D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
			"160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
			"909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
			"D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
			"855E6EEB22B3B2E5");

		Integer q("0xF518AA8781A8DF278ABA4E7D64B7CB9D49462353");		

		// Schnorr Group primes are of the form p = rq + 1, p and q prime. They
		// provide a subgroup order. In the case of 1024-bit MODP Group, the
		// security level is 80 bits (based on the 160-bit prime order subgroup).		

		// For a compare/contrast of using the maximum security level, see
		// dh-agree.zip. Also see http://www.cryptopp.com/wiki/Diffie-Hellman
		// and http://www.cryptopp.com/wiki/Security_level .

		DH dh;
		AutoSeededRandomPool rnd;

		dh.AccessGroupParameters().Initialize(p, q, g);

		if(!dh.GetGroupParameters().ValidateGroup(rnd, 3)) 
			throw runtime_error("Failed to validate prime and generator");

		size_t count = 0;

		p = dh.GetGroupParameters().GetModulus();
		q = dh.GetGroupParameters().GetSubgroupOrder();
		g = dh.GetGroupParameters().GetGenerator();
		
		// http://groups.google.com/group/sci.crypt/browse_thread/thread/7dc7eeb04a09f0ce
		Integer v = ModularExponentiation(g, q, p);
		if(v != Integer::One())
			throw runtime_error("Failed to verify order of the subgroup");

		//////////////////////////////////////////////////////////////

		SecByteBlock priv(dh.PrivateKeyLength());
		SecByteBlock pub(dh.PublicKeyLength());
		dh.GenerateKeyPair(rnd, priv, pub);
		printf("lengths: %d %d\n",dh.PrivateKeyLength(),dh.PublicKeyLength());
		byte* pubData = pub.data(); 	
		for(int j = 0; j < pub.size()-1; j++)
		    printf("%02X:", pubData[j]);	
		printf("%02X\n", pubData[pub.size()-1]);	
		// Send pub to Java
		sendData(pub.data(),pub.size());
		// Read pubB from Java
		byte pubBbytes[10000];
		int n = readData(pubBbytes,sizeof(pubBbytes));
		SecByteBlock pubB(pubBbytes,n);
		//////////////////////////////////////////////////////////////

		SecByteBlock sharedA(dh.AgreedValueLength());

		if(!dh.Agree(sharedA, priv, pubB))
			throw runtime_error("Failed to reach shared secret (1A)");


		//////////////////////////////////////////////////////////////

		Integer a;

		a.Decode(sharedA.BytePtr(), sharedA.SizeInBytes());
		cout << "Shared secret (A): " << std::hex << a << endl;
	}

	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		return -2;
	}

	catch(const std::exception& e)
	{
		cerr << e.what() << endl;
		return -1;
	}

	return 0;
}
