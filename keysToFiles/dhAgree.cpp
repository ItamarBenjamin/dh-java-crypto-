// g++ -g3 -ggdb -O0 -I. -I/usr/include/cryptopp dh-agree.cpp -o dh-agree.exe -lcryptopp -lpthread
// g++ -g -O2 -I. -I/usr/include/cryptopp dh-agree.cpp -o dh-agree.exe -lcryptopp -lpthread

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;
using std::ios;

#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fstream>

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

static string sJavaPubKeyFile = "/tmp/Java.pub";
static string sCryptoPrivKeyFile = "/tmp/Crypto.priv";
static string sCryptoPubKeyFile = "/tmp/Crypto.pub";

int filesize(const string filename)
{
    std::ifstream in(filename.c_str(), std::ifstream::ate | std::ifstream::binary);
    int size = in.tellg(); 
	in.close();
	return size;
}

int readFromFile(const string filename, unsigned char** result)
{
	int fileSize = filesize(filename);
	*result = new unsigned char[fileSize];
    std::ifstream in(filename.c_str(), ios::binary | ios::in);
	in.read((char*) *result,fileSize);
	in.close();
	return fileSize;
}

void writeToFile(const unsigned char* data, int size, const string filename)
{
	std::ofstream out(filename.c_str(), ios::binary | ios::out);
	out.write((const char*) data,size);
	out.close();
}

void printKey(string name, unsigned char* arr, int size)
{
	printf("Key %s %d: ",name.c_str(),size);
	for(int j = 0; j < size-1; j++)
		printf("%02X:", arr[j]);	
	printf("%02X\n", arr[size-1]);	
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

			if (argc != 2)
			{
				printf("use generate or agree\n");
				exit(1);
			}
			if (!strcmp(argv[1],"generate"))
			{
				SecByteBlock priv(dh.PrivateKeyLength());
				SecByteBlock pub(dh.PublicKeyLength());
				dh.GenerateKeyPair(rnd, priv, pub);
				
				printKey("Public", pub.data(), pub.size());
				printKey("Private", priv.data(), priv.size());
		
				// Write public key
				writeToFile(pub.data(),pub.size(),sCryptoPubKeyFile);
				// Write private key
				writeToFile(priv.data(),priv.size(),sCryptoPrivKeyFile);
			} else if (!strcmp(argv[1],"agree"))
			{
				unsigned char* pubBRaw;
				int lpubB = readFromFile(sJavaPubKeyFile,&pubBRaw);
				unsigned char* privRaw;
				int lpriv = readFromFile(sCryptoPrivKeyFile,&privRaw);
				unsigned char* pubRaw;
				int lpub = readFromFile(sCryptoPubKeyFile,&pubRaw);
				SecByteBlock pubB(pubBRaw,lpubB);
				printKey("Public B", pubBRaw,lpubB);
				SecByteBlock pub(pubRaw,lpriv);
				printKey("Public", pubRaw,lpriv);
				SecByteBlock priv(privRaw,lpub);
				printKey("Private", privRaw,lpub);
				
				SecByteBlock sharedA(dh.AgreedValueLength());

				if(!dh.Agree(sharedA, priv, pubB))
					throw runtime_error("Failed to reach shared secret (1A)");
				
				Integer a;

				a.Decode(sharedA.BytePtr(), sharedA.SizeInBytes());
				cout << "Shared secret (A): " << std::hex << a << endl;
			} else
			{
				printf("Unknown option %s\n",argv[1]);
				exit(1);
			}
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


