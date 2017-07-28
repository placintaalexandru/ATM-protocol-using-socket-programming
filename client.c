#include "lib.h"

/*
Creeaza un descriptor de fisier avand numele
"client-PID.log"

@param pid - pidul procesului ce ruleaza executabilul
@return descriptorul aferent fisierului
*/
int createFile(int pid) {
	char buffer[LOG_LEN];
	int fileId;

	memset(buffer, 0, LOG_LEN);
	strcat(buffer, "client-");
	snprintf(buffer + strlen(buffer), LOG_LEN - strlen(buffer), "%d", pid);
	strcat(buffer, ".log");
	fileId = open(buffer, O_WRONLY | O_CREAT, 0644);

	return fileId;
}

/*
Scrie in fisier un sir de caractere si intoarce numarul de
octeti scrisi in fisier

@param fileId - descriptorul fisierului in care se scrie
@param info - pointer ce contine adresa zonei de memorie a sirului ce se scrie
@return numarul de octeti scriti
*/
int writeToFile(int fileId, char *info) {
	int writtenInfo;

	writtenInfo = write(fileId, info, strlen(info));
	return writtenInfo;
}

/*
Executa operatia aferenta operatiunilor de login, logout, listsold,
getmoney, putmoney
Verific daca clientul curent este logat, caz in care nu efectuez operatia
de login, si afisez un mesaj corespunzator atat la stdout, cat si in fisierul
de log, sau daca nu sunt afisez un mesaj descriptiv in cazul incare se doreste
efectuarea altor operatiuni: logout, listsold, getmoney, putmoney

@pararm socket - descriptorului socket-ului pe care se trimite informatia
@param logFile - descriptorul de fisier in care se scrie istoricul operatiunilor
@param value - valoare de referinta in functie de tipul operatiei
@param message - pointer catre inceputul sirului de caractere aferent erorii
@param buffer - pointer catre inceputul sirului de caractere ce se va transmite
*/
void executeOperation(int socket, int logFile, bool loggedIn, bool value, char *message, char *buffer) {
	if (loggedIn == value) {
		printf("%s\n\n", message);
		writeToFile(logFile, message);
		writeToFile(logFile, "\n\n");
	} else {
		send(socket, buffer, strlen(buffer), 0);
	}
}

/*
Dintr-o operatiune de login extrage numarul de card
Fac o copie a sirului, pentru a nu modifica mesajul
Pentru aceasta functie saprg in token-uri, iar apoi folosesc
ce de-al doilea cuvant, cel care are numarul de card, iar
apoi folosesc functia atoi pentru a-l converti la int

@param buf - pointer catre zona de memorie ce contine sirul de 
			caractere ce contine comanda login
@return - numarul de card
*/
int getCardNumber(char *buf) {
	char *aux, *token;
	int cardNumber;

	aux = strdup(buf);
	token = strtok(aux, " \n");
	token = strtok(NULL, " \n");

	if (token == NULL) {
		return -1;
	}
	
	cardNumber = atoi(token);

	memset(aux, 0, strlen(buf));
	free(aux);
	return cardNumber;
}

/*
Executa operaiunea de unlock candse citeste de la intrarea standard se citeste
un sir de caractere ce inepe cu unlock.
Trimit pe socket-ul UDP mesajul citit, iar apoi trimit mesajul.
Dupa ce l-am trimis, astept un raspuns, iar daca numarul de octeti primiti
este mai mare decat 0, mesajul este valid si nu au aparut erori de transmisie,
verific ce primesc de la server, pentru a sti formatul in care scriu in fisier, sau daca
mai trebuie sa transmit alte date server-ului

@param unlockSocket - descriptorul socket-ului UDP pe care se face comunicarea pentru
						operatiunea de login
@param logFile - descriptorul fisierului in care scriu istoricul operatiunilor clientului
@param buffer - pointer catre zona de memorie in care primesc mesajele sau din care trimit mesajele
@param serverAddress - pointer care retine informatiile despre server, unde trebuie sa ajunga datele
						scrise pe socket
*/
void unlock(int unlockSocket, int logFile, int lastCard,
			char *buffer, struct sockaddr *serverAddress) {
	unsigned int size = sizeof(struct sockaddr);
	int n;
	char aux[MAX];													// citesc parola secreta

	sendto(unlockSocket, buffer, strlen(buffer), 0, serverAddress, size);
	memset(buffer, 0, MAX);
	n = recvfrom(unlockSocket, buffer, MAX, 0, serverAddress, &size);
	
	if (n > 0) {													// tratez posibilele cazuri pe care le poate primi clientul
		if (strstr(buffer, WRONG_CARD1) != NULL) {					// primesc eroare de numar card gresit
			printf("%s\n\n", buffer);
			writeToFile(logFile, buffer);
			writeToFile(logFile, "\n\n");
		} else if (strstr(buffer, FAILED_UNLOCK) != NULL) {			// parola nu corespunde, deci deblocare esuata
			printf("%s\n\n", buffer);
			writeToFile(logFile, buffer);
			writeToFile(logFile, "\n\n");
		} else if (strstr(buffer, "Trimite") != NULL) {				// primesc mesaj de trimitere a parolei secrete
	 		printf("%s\n", buffer);
			writeToFile(logFile, buffer);
			writeToFile(logFile, "\n");

			memset(aux, 0, MAX);
			memset(buffer, 0, MAX);
			fgets(aux, MAX - 1, stdin);
			fflush(stdin);
			writeToFile(logFile, aux);

			snprintf(buffer, MAX, "%d", lastCard);					// realizez constructia <numar_card> <parola_secreta>
			strcat(buffer, " ");
			strcat(buffer, aux);

			sendto(unlockSocket, buffer, strlen(buffer), 0, serverAddress, size);			// trimit la server
			memset(buffer, 0, MAX);
			recvfrom(unlockSocket, buffer, MAX, 0, serverAddress, &size);					// astept raspunsul
			printf("%s\n\n", buffer);
			writeToFile(logFile, buffer);
			writeToFile(logFile, "\n\n");
		} else {
			printf("%s\n\n", buffer);
			writeToFile(logFile, buffer);
			writeToFile(logFile, "\n\n");
		}
	}
}

/*
Executa operatiunea de inchidere a clientului
Trimit mesajul de anuntare server-ului, iar apoi anunt
utilizatorul ca se va inchide clientul prin afisarea unui mesaj la
iesirea standard

@param publicSocket - descriptorul socket-ului TCP prin intermediul
						caruia se comunica cu server-ul
@param logFile - descriptorul fisierului in care se scrie istoricul
					actiunilor
@param buffer - pointer catre zona de memorie in care este stocat sirul
				de caractere ce se trimite, respectiv afiseaza
*/
void quit(int publicSocket, int logFile, char *buffer) {
	send(publicSocket, buffer, strlen(buffer), 0);
	memset(buffer, 0, MAX);
	printf("%s", buffer);
	writeToFile(logFile, buffer);
}

/*
Creeaza un mesaj de unlock pe care il trimite server-ului

@param buffer - pointer catre o zona de memorie unde se va retine mesajul
@param lastCard - numarul de card al ultimului card cu care s-a incerca login-ul
*/
void createUnlockMessage(char *buffer, int lastCard) {
	memset(buffer, 0, MAX);
	strcat(buffer, UNLOCK);
	strcat(buffer, " ");
	snprintf(buffer + strlen(buffer), MAX - strlen(buffer), "%d", lastCard);
}

int main(int argc, char *argv[]) {
	bool loggedIn = false;
	int publicSocket, maxSocketValue, n, i, logFile, unlockSocket, lastCard = -1;
	struct sockaddr_in serverAddress;
	char buffer[MAX];
	fd_set readSet, temporarySet;

	if (argc < 3) {
		printf("./client IP_SERVER PORT_SERVER\n");
		return 0;
	}
																	// verific daca descriptorii sunt valizi, daca gasesc unul invalid inchid tot 
	logFile = createFile(getpid());
	if (logFile < 0) {
		printf("%s eroare creare fisier log client.c\n", FUNCTION_CALL_FAIL);
		return -1;
	}

	publicSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (publicSocket < 0) {
		close(logFile);
		printf("Eroare socket TCP\n");
		writeToFile(logFile, FUNCTION_CALL_FAIL);
		return -1;
	}
	
	unlockSocket = socket(PF_INET, SOCK_DGRAM, 0);
	if (unlockSocket < 0) {
		close(logFile);
		printf("Eroare socket UDP\n");
		writeToFile(logFile, FUNCTION_CALL_FAIL);
		return -1;
	}

	serverAddress.sin_family = AF_INET;								// setez adresa si portul server-ului, pentru a-i fi cunoscute clientului
	serverAddress.sin_port = htons(atoi(argv[2]));
	inet_aton(argv[1], &serverAddress.sin_addr);

	memset(buffer, 0, MAX);
	FD_ZERO(&readSet);
	FD_ZERO(&temporarySet);
	FD_SET(publicSocket, &readSet);
	FD_SET(0, &readSet);
	maxSocketValue = publicSocket > unlockSocket ? publicSocket : unlockSocket;

	if (connect(publicSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
		writeToFile(logFile, FUNCTION_CALL_FAIL);
		return -1;
	}
	
	while(1) {
		temporarySet = readSet; 
		if (select(maxSocketValue + 1, &temporarySet, NULL, NULL, NULL) == -1) {
			writeToFile(logFile, FUNCTION_CALL_FAIL);
			writeToFile(logFile, " select client.c\n");
			close(unlockSocket);
			close(publicSocket);
			close(logFile);
			return -1;
		}
													// parcurg lista de descriptori
		for (i = 0; i <= maxSocketValue; i++) {
			if (FD_ISSET(i, &temporarySet)) {	
				if (i == 0) {
					memset(buffer, 0 , MAX);
					fgets(buffer, MAX-1, stdin);
					writeToFile(logFile, buffer);
															// citesc de la tastatura si in functie de mesaj execut operatia
					if (strncmp(buffer, LOGIN, 5) == 0) {
						executeOperation(publicSocket, logFile, loggedIn, true, SESION_ACTIVE, buffer);
						lastCard = getCardNumber(buffer);
					} else if (strncmp(buffer, LOGOUT, 6) == 0) {
						executeOperation(publicSocket, logFile, loggedIn, false, CLIENT_NOT_LOGGED, buffer);
						loggedIn = false;
					} else if (strncmp(buffer, LISTSOLD, 8) == 0) {
						executeOperation(publicSocket, logFile, loggedIn, false, CLIENT_NOT_LOGGED, buffer);
					} else if (strncmp(buffer, GETMONEY, 8) == 0) {
						executeOperation(publicSocket, logFile, loggedIn, false, CLIENT_NOT_LOGGED, buffer);
					} else if (strncmp(buffer, PUTMONEY, 8) == 0) {
						executeOperation(publicSocket, logFile, loggedIn, false, CLIENT_NOT_LOGGED, buffer);
					} else if (strncmp(buffer, QUIT, 4) == 0) {
						quit(publicSocket, logFile, buffer);
						close(logFile);
						close(unlockSocket);
						close(publicSocket);
						return 0;
					} else if (strncmp(buffer, UNLOCK, 6) == 0) {
						createUnlockMessage(buffer, lastCard);
						unlock(unlockSocket, logFile, lastCard, buffer, (struct sockaddr *)&serverAddress);
					}
			 	} else {													    // astept raspuns pe socket-ul TCP de la server
					while ((n = recv(publicSocket, buffer, MAX, 0)) <= 0);
					if (n > 0) {
						printf("%s", buffer);

						if (strncmp(buffer, "ATM> Welcome", 12) == 0) {			// primesc mesaj de login pozitiv
							loggedIn = true;
						} else if (strstr(buffer + 5, QUIT) != NULL) {			// primesc mesaj de anuntare ca server-ul se inchide
							close(unlockSocket);
							close(publicSocket);
							close(logFile);
							return 0;
						}

						writeToFile(logFile, buffer);							// scriu in fisierul de log raspunsul de la server
						writeToFile(logFile, "\n");
						memset(buffer, 0, MAX);
						printf("\n");
					}
				}
			}
		}
	}

	return 0;
}