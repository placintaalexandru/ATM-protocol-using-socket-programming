#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdbool.h>

#define NAME 13
#define SECRET_PASS 17
#define MAX 250
#define BLOCK_CHANCES 3
#define LOG_LEN 30

#define ATM_PREFIX "ATM> "
#define UNLOCK_PREFIX "UNLOCK> "
#define LOGIN "login"
#define LOGOUT "logout"
#define LISTSOLD "listsold"
#define DISCONNECT "Deconectare de la bancomat"
#define GETMONEY "getmoney"
#define PUTMONEY "putmoney"
#define UNLOCK "unlock"
#define QUIT "quit"

#define CLIENT_NOT_LOGGED "-1 : Clientul nu este autentificat"
#define SESION_ACTIVE "-2 : Sesiune deja deschisa"
#define WRONG_PIN "-3 : Pin gresit"
#define WRONG_CARD "-4 : Numar card inexistent\n"
#define WRONG_CARD1 "-4 : Numar card inexistent"
#define BLOCKED_CARD "-5 : Card blocat"
#define FAILED_OPERATION "-6 : Operatie esuata"
#define FAILED_UNLOCK "-7 : Deblocare esuata"
#define INSUFICIENT_FUNDS "-8 : Fonduri insuficiente"
#define ATM_POLICY "-9 : Suma nu e multiplu de 10"
#define FUNCTION_CALL_FAIL "-10 : Eroare la apel de procedura"
#define INLCOMPLETE_COMMAND "-11 : Comanda nu contine toti parametri\n"


typedef enum {
	BLOCKED,
	UNBLOCKED
} CardStatus;

typedef struct {
	char *name;
	char *prename;
	int cardNumber;
	int pin;
	char *secretPassword;
	double sold;
	int numberOfTries;
	CardStatus cardStatus;
} ClientAccount;

typedef struct ListCel {
	int cardNumber;
	int socket;
	struct ListCel *urm;
} ListCel;


/*
Creeaza un pointer la o zona de memorie unde e alocata o structura
pentru un cont cu detaliile specificate de parametrii respecitivi

@param name - numele
@param prename - prenumele
@param cardNumber - numar de card
@param pin - pin-ul contului
@param secretPassword - parola secreta
@param sold - soldul contului
@return pointer catre o zona de memorie unde e alocata o structura
*/
ClientAccount *createAccount(char *name, char *prename,
							unsigned int cardNumber,
							unsigned int pin,
							char *secretPassword,
							double sold) {
	ClientAccount *account;

	account = calloc(1, sizeof(ClientAccount));
	if (!account) {
		return NULL;
	}

	account->name = strdup(name);
	account->prename = strdup(prename);
	account->cardNumber = cardNumber;
	account->pin = pin;
	account->secretPassword = strdup(secretPassword);
	account->sold = sold;
	account->cardStatus = UNBLOCKED;

	return account;
}

/*
Elibereaza memeoria pentru o structura pentru un cont

@param clientAccount - adresa zonei de memorie unde e alocata o structura de tip cont
*/
void deleteAccount(ClientAccount *clientAccount) {
	free(clientAccount->name);
	free(clientAccount->prename);
	free(clientAccount->secretPassword);
	free(clientAccount);
}

/*
Elibereaza memoria alocata pentru baza de date

@param database - baza de date a clientilor
@param clients - numarul de clienti
*/
void deleteDataBase(ClientAccount **dataBase,
					unsigned int clients) {
	int i;

	for (i = 0; i < clients; i++) {
		deleteAccount(dataBase[i]);
	}

	free(dataBase);
}

/*
Citeste datele din fisier

@param fileName - nuemele fisierului
@param cleints - adresa unei variabile in care retin numarul de clienti
@return pointer-ul de pointeri ce contine detaliile tuturor clientilor
*/
ClientAccount **readCredentialFile(const char *fileName, unsigned int *clients) {
	FILE *inputFile;
	char name[NAME], prename[NAME], secretp[SECRET_PASS];
	unsigned int i, card, pin;
	double amount;
	ClientAccount **clientVector;

	inputFile = fopen(fileName, "r");
	if (!inputFile) {
		return NULL;
	}

	fscanf(inputFile,"%u", clients);

	clientVector = calloc(*clients, sizeof(ClientAccount *));
	if (!clientVector) {
		return NULL;
	}

	for (i = 0; i < *clients; i++) {
		fscanf(inputFile, "%s %s %u %u %s %lf", name, prename, &card, &pin, secretp, &amount);
		
		clientVector[i] = createAccount(name, prename, card, pin, secretp, amount);
		if (!clientVector[i]) {
			int j;

			for (j = 0; j < i; j++) {
				free(clientVector[i]);
			}

			return NULL;
		}
	}

	fclose(inputFile);
	return clientVector;
}
