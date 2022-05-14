#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

using namespace std;
#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "cryptopp/des.h"
using CryptoPP::DES;

#include "cryptopp/modes.h"
using CryptoPP::CBC_Mode;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include <mpi.h>

#include <fstream>
using std::ifstream;

//Intenta usar una llave.
string tryKey(CBC_Mode< DES >::Decryption decryptor, string cipher, CryptoPP::byte key[DES::KEYLENGTH], CryptoPP::byte iv[DES::BLOCKSIZE]) {
	//Trata de decifrar el mensaje con la llave.
	string decrypted;
	decryptor.SetKeyWithIV(key, 8, iv);
	StringSource s(cipher, true, new StreamTransformationFilter(decryptor,new StringSink(decrypted), CryptoPP::BlockPaddingSchemeDef::ZEROS_PADDING)); 
	return decrypted;
}

//Compara si la palabra clave esta en el resultado de desencripción.
bool isKey(CBC_Mode< DES >::Decryption decryptor, string cipher, CryptoPP::byte key[DES::KEYLENGTH], CryptoPP::byte iv[DES::BLOCKSIZE]) {
	return tryKey(decryptor, cipher, key, iv).find("aventuras") != std::string::npos;	
}

int main(int argc, char* argv[]) {
	AutoSeededRandomPool prng;

	SecByteBlock key(8);
	prng.GenerateBlock(key, 8);

	CryptoPP::byte iv[DES::BLOCKSIZE] = {0};
	CryptoPP::byte key2[DES::KEYLENGTH] = {255, 0, 0, 0, 0, 0, 0, 0};

	string plain = "Pato aventuras con el pato luca y francisco";
	string cipher, encoded, line;
	ifstream myfile ("message.txt");
	string cipherText;
	if (myfile.is_open()) {
		while ( getline (myfile,line) ) {cipherText = line;}
		myfile.close();
	} else {
		cout << "No pude abrir el archivo";
	} 

	encoded.clear();
	StringSource(key2, 8, true, new HexEncoder(new StringSink(encoded)));

	try{
		CBC_Mode< DES >::Encryption encrypt;
		encrypt.SetKeyWithIV(key2, 8, iv);
		StringSource(plain, true, new StreamTransformationFilter(encrypt, new StringSink(cipher)));
	} catch(const CryptoPP::Exception& encrypt) {
		cerr << encrypt.what() << endl;
		exit(1);
	}

	encoded.clear();
	StringSource(cipher, true,new HexEncoder(new StringSink(encoded)));
	cout << encoded << endl;
	string tryMessage;
	StringSource(cipherText, true, new HexDecoder(new StringSink(tryMessage)));

	if(const CryptoPP::Exception& except) {
		cerr << except.what() << endl;
		exit(1);
	} else {
		//Se inicializa MPI
		unsigned char cipherSom[] = {108, 245, 65, 63, 125, 200, 150, 66, 17, 170, 207, 170, 34, 31, 70, 215, 0};
		int N, id;
		unsigned long long int up = (unsigned long long int)(pow(2, 64));
		unsigned long long int min, max;
		MPI_Status st;
		MPI_Request req;
		int flag;
		int ciphlen = *(&cipherSom + 1) - cipherSom;
		MPI_Comm comm = MPI_COMM_WORLD;
		MPI_Init(NULL, NULL);
		MPI_Comm_size(comm, &N);
		MPI_Comm_rank(comm, &id);
		//Calculo de limites del proceso
		long int nodeRange = up / N;
  		min = nodeRange * id;
  		max = nodeRange * (id+1) -1;
  		if(id == N-1) {max = up;}

  		long match = 0;
  		MPI_Irecv(&match, 1, MPI_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, comm, &req);

		double start, stop;
		start = MPI_Wtime();

		CBC_Mode< DES >::Decryption decrypt;
		unsigned long long int x = 0;
		unsigned char byteList[8];
		memcpy(byteList, &min, 8);
		for(unsigned long long int i = min; i < max && (match==0); ++i) {
			memcpy(byteList, &i, 8);
			if(isKey(decrypt, tryMessage, byteList, iv)) {
				match = 1;
				cout << "\nEncontré la palabra clave!\n" << endl;
				cout << "El mensaje desencriptado es: " << tryKey(decrypt, tryMessage, byteList, iv) << endl;
				stop = MPI_Wtime();
				cout << "Tiempo: " << stop-start << " segs " << endl;
				for(int node=0; node<N; node++) {MPI_Send(&match, 1, MPI_LONG, node, 0, MPI_COMM_WORLD);}
     			break;
			}

			MPI_Test(&req, &flag, &st);
			if (match) break;
		}
		MPI_Finalize();
		return 0;
	}

	return 0;
}