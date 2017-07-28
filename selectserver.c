#include "lib.h"

#define MAX_CLIENTS 20

extern ClientAccount **readCredentialFile(const char *fileName, unsigned int *clients);
extern void deleteDataBase(ClientAccount **dataBase, unsigned int clients);

/*
Adauga in lista simplu inlantuita de clienti activi o celula ce contine
un anumit numar de card si un socket ce reprezinta detaliile esentiale de
identificare ale contului respectiv

@param listAddress - adresa listei in care retin celule ce reprezinta detaliile
						esentiale ale conturilor de comunicare
@param cardNumber - numarul de card al contului
@param socket - socket-ul privat prin intermediul caruia clientul
				comunica cu server-ul
*/
void addNewActiveClient(ListCel **listAddress, int cardNumber, int socket) {
	ListCel *newCel;

	newCel = calloc(1, sizeof(ListCel));										// aloc o zona de memorie
	if (!newCel) {
		return;
	}

	newCel->cardNumber = cardNumber;											// setez specificatiile
	newCel->socket = socket;
	newCel->urm = *listAddress;
	*listAddress = newCel;
}

/*
Verifica daca un numar de card se gaseste deja in lista conturilor
care deja sunt atribuite clientilor ce comunica cu server-ul la
momentul respectiv
Parcurg lista pana cand gasesc un element care sa aiba numarul de
card respectiv

@param activeAccounts - lista in care retin elementele
@param cardNumber - numarul de card pentru care se verifica
@return valoare booleana care descrie valoare de adevar a incluziunii in lista
*/
bool checkIfUserActive (ListCel *activeAccounts, int cardNumber) {
	ListCel *cel;

	for (cel = activeAccounts; cel != NULL; cel = cel->urm) {
		if (cel->cardNumber == cardNumber) {
			return true;
		}
	}

	return false;
}

/*
Verifica daca exista deja un cont pe unul din lista conturilor active

@param activeAccounts - lista in care retin elementele
@param socket - numarul socket-ul pentru care se verifica
@return valoare booleana care descrie valoare de adevar a incluziunii in lista
*/
bool checkIfSessionActive (ListCel *activeAccounts, int socket) {
	ListCel *cel;

	for (cel = activeAccounts; cel != NULL; cel = cel->urm) {
		if (cel->socket == socket) {
			return true;
		}
	}

	return false;
}

/*
Intoarce un pointer catre o zona de memorie in care este alocat un cont
de utilizator

@param dataBase - pointer de pointeri ce contine utilizatorii
@param cardNumber - numarul de card al contului care se doreste
@param clients - numarul de clienti din baza de date
@return un pointer la o zona de memorie unde este alocata o structura
		pentru un cont de utilizator
*/
ClientAccount *getUserAccount(ClientAccount **dataBase, int cardNumber,
								unsigned int clients) {
	unsigned int i;

	for (i = 0; i < clients; i++) {
		if (dataBase[i]->cardNumber == cardNumber) {
			return dataBase[i];
		}
	}

	return NULL;
}

/*
Cauta in lista de conturi active numarul de card care se afla pe socket-ul
respectiv si il returneaza, sau -1 in caz ca nu exista

@param activeAccounts - lista conturilor active
@param socket - socket-ul dupa care se cauta
@return numarul de card al contului
*/
int getCardNumberFromSocket(ListCel *activeAccounts, int socket) {
	ListCel *current;

	for (current = activeAccounts; current != NULL; current = current->urm) {
		if (current->socket == socket) {
			return current->cardNumber;
		}
	}

	return -1;
}

/*
Sterge din lista un element care este pe socket-ul primit ca parametru

@param activeAccounts - lista
@param socket - socket-ul care se doreste eliminat
@return 1 in caz de succes si -1 altfel
*/
int removeFromActiveAccount(ListCel **activeAccounts, int socket) {
	ListCel *current, *previous = NULL;

	for (current = *activeAccounts; current != NULL; previous = current, current = current->urm) {
		if (current->socket == socket) {
			if (previous == NULL) {
				*activeAccounts = current->urm;
			} else {
				previous->urm = current->urm;
			}

			free(current);
			return 1;
		}
	}

	return -1;
}

/*
Realizeaza raspunsul pentru operatia de unlock din partea server-ului
Verifica daca cardul este deja deblocat, daca numarul de card este invalid
si trimite raspunsul corespunzator clientului

@param messageReceived - mesajul primit de la client
@param database - baza de data a clientilor
@param clients - numarul de clienti
@param unlockSocket - descriptorul socket-ului UDP prin care server-ul
						comunica cu clientul
@param clientAddress - datele clientului
*/
void unlockAnswer(char *messageReceived, ClientAccount **dataBase,
					unsigned int clients, int unlockSocket,
					struct sockaddr *clientAddress) {
	int cardNumber;
	char *secretPassword, *token;
	ClientAccount *account;

	token = strtok(messageReceived, " \n");
	token = strtok(NULL, " \n");
	secretPassword = strtok(NULL, " \n");
													// verific daca comadna unlock este completa
	if (token == NULL) {
		memset(messageReceived, 0, MAX);
		strcat(messageReceived, UNLOCK_PREFIX);
		strcat(messageReceived, INLCOMPLETE_COMMAND);
		return;
	} else {
		cardNumber = atoi(token);
	}

	account = getUserAccount(dataBase, cardNumber, clients);		// verific daca contul este valid
	if (account == NULL) {
		memset(messageReceived, 0, MAX);
		strcat(messageReceived, UNLOCK_PREFIX);
		strcat(messageReceived, WRONG_CARD1);
	} else {
		if (account->cardStatus == UNBLOCKED) {					// verifica daca contul este deja deblocat
			memset(messageReceived, 0, MAX);
			strcat(messageReceived, UNLOCK_PREFIX);
			strcat(messageReceived, FAILED_OPERATION);
		} else if (secretPassword != NULL) {									// am primit si parola secreta in acelasi timp
			if (strcmp(secretPassword, account->secretPassword) == 0) {				// verific daca parolele se potrivesc
				account->cardStatus = UNBLOCKED;
				account->numberOfTries = 0;

				memset(messageReceived, 0, MAX);
				strcat(messageReceived, UNLOCK_PREFIX);
				strcat(messageReceived, "Client deblocat");
			} else {
				memset(messageReceived, 0, MAX);
				strcat(messageReceived, UNLOCK_PREFIX);
				strcat(messageReceived, FAILED_UNLOCK);				
			}
		} else {															// trimit mesaj de trimitere a parolei secrete
			unsigned int size = sizeof(struct sockaddr), n;
			char buffer[MAX];

			memset(messageReceived, 0, MAX);
			strcat(messageReceived, UNLOCK_PREFIX);
			strcat(messageReceived, "Trimite parola secreta");
			
			sendto(unlockSocket, messageReceived, strlen(messageReceived), 0, clientAddress, size);

			while ((n = recvfrom(unlockSocket, buffer, MAX, 0, clientAddress, &size)) <= 0);		// astept parola secreta
			
			secretPassword = strtok(buffer, " \n");
			secretPassword = strtok(NULL, " \n");

			if (strcmp(account->secretPassword, secretPassword) == 0) {								// verific daca parolele se potrivesc
				account->cardStatus = UNBLOCKED;
				account->numberOfTries = 0;

				memset(messageReceived, 0, MAX);
				strcat(messageReceived, UNLOCK_PREFIX);
				strcat(messageReceived, "Client deblocat");
			} else {
				memset(messageReceived, 0, MAX);
				strcat(messageReceived, UNLOCK_PREFIX);
				strcat(messageReceived, FAILED_UNLOCK);
			}
		}
	}
}

/*
Realizeaza raspunsul pe socket-ul TCP al server-ului la
una din operatiile: login ,logout, listsold, getmoney sau putmoney
Pentru fiecare din operatiile de mai sus verific daca comanda este completa, iar
apoi daca indeplineste corectitudinea

@param messageReceived - mesajul primit de la client
@param database - baza de data in care retin conturile
@param clients- numarul de clienti
@param currentUsers - adresa listei utilizatorilor activi
@connectedDevices - lista dispozitivelior conectate, socket-urilor acestora
@param socket - socket-ul pe TCP pe care se raspunde
*/
void answer(char *messageReceived, ClientAccount **dataBase, unsigned int clients,
			ListCel **currentUsers, ListCel **connectedDevices,	int socket) {
	char *token;
	ClientAccount *account;

	if (strncmp(messageReceived, LOGIN, 5) == 0) {    // primesc comanda de login
		int cardNumber, pin;
		
		token = strtok(messageReceived, " \n");
		token = strtok(NULL, " \n");
		
		if (token == NULL) {
			memset(messageReceived, 0, MAX);
			strcat(messageReceived, ATM_PREFIX);
			strcat(messageReceived, INLCOMPLETE_COMMAND);
			return;
		} else {
			cardNumber = atoi(token);
		}

		token = strtok(NULL, " \n");
		if (token == NULL) {
			memset(messageReceived, 0, MAX);
			strcat(messageReceived, ATM_PREFIX);
			strcat(messageReceived, INLCOMPLETE_COMMAND);
			return;
		} else {
			pin = atoi(token);
		}

		memset(messageReceived, 0, MAX);
		strcat(messageReceived, ATM_PREFIX);
		account = getUserAccount(dataBase, cardNumber, clients);

		if (!account) {
			strcat(messageReceived, WRONG_CARD);
			return;
		} else {
			if (checkIfSessionActive(*currentUsers, socket) == true) {			// verific adaca clientul e deja conectat
				strcat(messageReceived, SESION_ACTIVE);
			} else if (checkIfUserActive(*currentUsers, cardNumber) == true) {  // verific daca utilizatorul e deja conectat
				strcat(messageReceived, SESION_ACTIVE);
			} else if (account->cardStatus == BLOCKED) {						// verific daca contul e blocat
				strcat(messageReceived, BLOCKED_CARD);
			} else if (account->pin != pin) {									// verific daca pin-urile corespund
				account->numberOfTries++;
				if (account->numberOfTries == BLOCK_CHANCES) {					// verific daca s-au introdus numarul maxim deincercari
					strcat(messageReceived, BLOCKED_CARD);
					account->cardStatus = BLOCKED;
				} else {
					strcat(messageReceived, WRONG_PIN);
				}
			} else {														    // resetez numarul de incercari
				account->numberOfTries = 0;
				strcat(messageReceived, "Welcome ");
				strcat(messageReceived, account->name);
				strcat(messageReceived, " ");
				strcat(messageReceived, account->prename);
				addNewActiveClient(currentUsers, cardNumber, socket);
			}
		}
	} else if (strncmp(messageReceived, LOGOUT, 6) == 0) {						// primesc comanda de logout
		memset(messageReceived, 0, MAX);
		strcat(messageReceived, ATM_PREFIX);

		if (removeFromActiveAccount(currentUsers, socket) == -1) {				// verific daca contul de pe acel socket avea un numar de card
			strcat(messageReceived, CLIENT_NOT_LOGGED);
		} else {
			strcat(messageReceived, DISCONNECT);
		}
	} else if (strncmp(messageReceived, LISTSOLD, 8) == 0) {					// se primeste comanda de listare a sold-ului
		int cardNumber;

		memset(messageReceived, 0, MAX);
		strcat(messageReceived, ATM_PREFIX);

		cardNumber = getCardNumberFromSocket(*currentUsers, socket);			// preiau numarul de card din lista de conturi active
		if (cardNumber == -1) {													// daca numarul de card e -1 inseaman ca clientul nu avea un cont asociat
			strcat(messageReceived, CLIENT_NOT_LOGGED);
		} else {
			int i;

			account = getUserAccount(dataBase, cardNumber, clients);
			snprintf(messageReceived + strlen(messageReceived), MAX - strlen(messageReceived), "%lf", account->sold);

			for (i = 0; i < strlen(messageReceived); i++) {
				if (messageReceived[i] == '.') {
					memset(messageReceived + i + 3, 0, MAX - i - 3);
				}
			}
		}
	} else if (strncmp(messageReceived, GETMONEY, 8) == 0) {					// se primeste comanda de retragere numerar
		int sumToGet;

		token = strtok(messageReceived, " ");									// verific daca comanda are toti parametrii
		token = strtok(NULL, " ");
		if (token == NULL) {
			memset(messageReceived, 0, MAX);
			strcat(messageReceived, ATM_PREFIX);
			strcat(messageReceived, INLCOMPLETE_COMMAND);
			return;
		} else {
			sumToGet = atoi(token);
		}

		memset(messageReceived, 0, MAX);
		strcat(messageReceived, ATM_PREFIX);

		if (sumToGet % 10) {													// verific corectitudinea sumei de retras
			strcat(messageReceived, ATM_POLICY);
		} else {
			int cardNumber;

			cardNumber = getCardNumberFromSocket(*currentUsers, socket);		// preiau numarul de card asociat socket-ului
			if (cardNumber == -1) {
				strcat(messageReceived, CLIENT_NOT_LOGGED);
			} else {
				account = getUserAccount(dataBase, cardNumber, clients);		// preiau contul cu acel numar de card

				if (sumToGet < 0) {
					strcat(messageReceived, FAILED_OPERATION);					// nu pot retrage suma negativa
				} else if (sumToGet > account->sold) {
					strcat(messageReceived, INSUFICIENT_FUNDS);					// vad daca suma e mai mare decat soldul curent
				} else {
					strcat(messageReceived, "Suma ");
					snprintf(messageReceived + strlen(messageReceived), MAX - strlen(messageReceived), "%d", (int)sumToGet);
					strcat(messageReceived, " retrasa cu succes");
					account->sold -= sumToGet;
				}
			}
		}
	} else if (strncmp(messageReceived, PUTMONEY, 8) == 0) {					// se primeste comanda de depunere numerar
		double sumToPut;

		token = strtok(messageReceived, " ");
		token = strtok(NULL, " ");

		if (token == NULL) {													// verific daca comanda e completa
			memset(messageReceived, 0, MAX);
			strcat(messageReceived, ATM_PREFIX);
			strcat(messageReceived, INLCOMPLETE_COMMAND);
			return;
		} else {
			sumToPut = atof(token);
		}

		memset(messageReceived, 0, MAX);
		strcat(messageReceived, ATM_PREFIX);

		if (sumToPut < 0) {														// nu pot depune o suma negativa
			strcat(messageReceived, FAILED_OPERATION);
		} else {
			int cardNumber;

			cardNumber = getCardNumberFromSocket(*currentUsers, socket);		// preiau numarul de card asociat socket-ului
			if (cardNumber == -1) {
				strcat(messageReceived, CLIENT_NOT_LOGGED);
			} else {
				account = getUserAccount(dataBase, cardNumber, clients);		// preiau contul cu acel numar de card
				account->sold += sumToPut;
				snprintf(messageReceived + strlen(messageReceived), MAX - strlen(messageReceived), "%s", "Suma depusa cu succes");
			}
		}
	} else if (strncmp(messageReceived, QUIT, 4) == 0) {						// clientul respectiv se inchide
		removeFromActiveAccount(currentUsers, socket);							// il sterg din lista de conturi active
		removeFromActiveAccount(connectedDevices, socket);						// il sterg din lista de clienti conectati
	}

	strcat(messageReceived, "\n");
}

/*
Realizeaza inchiderea server-ului, anuntand clientii de inchiderea acestuia

@param dataBase - baza de data in care retin clientii
@param connectedDEvices - lista clientilor de la un moentdat, nu neparat logati
@param activeAccounts - lista clientilor logati
@param clients - numarul de clienti
@param buffer - pointer catre zona de mmeorie unde este sirul de caractere ce se va trimite
				tuturor clientilor
*/
void serverQuit(ClientAccount **dataBase, ListCel *connectedDevices,
				ListCel *activeAccounts, unsigned int clients, char *buffer) {
	ListCel *current, *previous;

	memset(buffer, 0, MAX);
	strcat(buffer, ATM_PREFIX);
	strcat(buffer, "quit\n");
	deleteDataBase(dataBase, clients);

	for (current = connectedDevices; current != NULL; ) {				// parcurg lista clientilor conectati si o golesc
		removeFromActiveAccount(&activeAccounts, current->socket);
		send(current->socket, buffer, strlen(buffer), 0);
		previous = current;
		current = current->urm;
		printf("Se inchide clientul de pe socket-ul %d\n", previous->socket);
		free(previous);
	}

	for (current = activeAccounts; current != NULL; ) {					// parcurg lista clientilor logati si o golesc
		send(current->socket, buffer, strlen(buffer), 0);
		previous = current;
		current = current->urm;
		printf("Se inchide clientul de pe socket-ul %d\n", previous->socket);
		free(previous);
	}
}

int main(int argc, char *argv[]) {
	int publicSocket, unlockSocket, privateSocket, port, n, i, maxSocketValue, ok;
	char buffer[MAX];
	struct sockaddr_in serverAddress, clientAddress;
	unsigned int clients, size;
	bool quit = false;
	ClientAccount **dataBase;
	socklen_t clilen;
	ListCel *activeClients, *connectedDevices;
	fd_set readSet, temporarySet;

	if (argc < 3) {
	 	printf("./server PORT FISIER_SURSA\n");
	 	return 0;
	}

	ok = 1;
	clilen = sizeof(struct sockaddr_in);
	activeClients = NULL;
	connectedDevices = NULL;
	memset(buffer, 0, MAX);
	memset((char *) &serverAddress, 0, sizeof(struct sockaddr_in));
	FD_ZERO(&readSet);
	FD_ZERO(&temporarySet);
	 
	publicSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (publicSocket < 0) {
	 	printf("Eroare socket TCP public\n");
	 	return -1;
	}
	 
	unlockSocket = socket(PF_INET, SOCK_DGRAM, 0);
	if (unlockSocket < 0) {
	 	printf("Eroare socket UDP\n");
	 	close(publicSocket);
	 	return -1;
	}

	port = atoi(argv[1]);
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_addr.s_addr = INADDR_ANY;
	serverAddress.sin_port = htons(port);
	
	setsockopt(publicSocket, SOL_SOCKET, SO_REUSEADDR, &ok, sizeof(ok));
	if (bind(publicSocket, (struct sockaddr *)&serverAddress, sizeof(struct sockaddr)) < 0) {
	 	printf("Eroare bind socket TCP public\n");
	 	close(publicSocket);
	 	close(unlockSocket);
	 	return -1;
	}

	setsockopt(unlockSocket, SOL_SOCKET, SO_REUSEADDR, &ok, sizeof(ok));
	if (bind(unlockSocket, (struct sockaddr *)&serverAddress, sizeof(struct sockaddr)) < 0) {
	 	printf("Eroare bin socket UDP\n");
	 	close(publicSocket);
	 	close(unlockSocket);
	 	return -1;
	}

	listen(publicSocket, MAX_CLIENTS);
	FD_SET(publicSocket, &readSet);
	FD_SET(0, &readSet);
	FD_SET(unlockSocket, &readSet);
	
	maxSocketValue = unlockSocket > publicSocket ? unlockSocket : publicSocket;
	dataBase = readCredentialFile(argv[2], &clients);
	size = sizeof(struct sockaddr);

	while (1) {
		temporarySet = readSet; 
		if (select(maxSocketValue + 1, &temporarySet, NULL, NULL, NULL) == -1) {
			printf("%s select server\n", FUNCTION_CALL_FAIL);
			close(unlockSocket);
			close(privateSocket);
			return -1;
		}

		for (i = 0; i <= maxSocketValue; i++) {
			if (quit == true) {
				serverQuit(dataBase, connectedDevices, activeClients, clients, buffer);
				close(unlockSocket);
				close(publicSocket);
				return 0;
			}

			if (FD_ISSET(i, &temporarySet)) {
				if (i == 0) {
					memset(buffer, 0, MAX);
					fgets(buffer, MAX - 1, stdin);
					if (strncmp(buffer, QUIT, 4) == 0) {
						printf("Server-ul se va inchide\n");
						quit = true;
					}
				} else if (i == publicSocket) {											// conexiune noua
					if ((privateSocket = accept(publicSocket, (struct sockaddr *)&clientAddress, &clilen)) == -1) {
						printf("%s accept server\n", FUNCTION_CALL_FAIL);
						close(unlockSocket);
						close(publicSocket);
						return -1;
					}

					FD_SET(privateSocket, &readSet);									// adaug socket-ul privat
					addNewActiveClient(&connectedDevices, -1, privateSocket);
					maxSocketValue = privateSocket > maxSocketValue ? privateSocket : maxSocketValue;		
				} else if (i == unlockSocket) {															// primesc mesaj pe socket-ul UDP
					memset(buffer, 0, MAX);
					recvfrom(unlockSocket, buffer, MAX, 0, (struct sockaddr*)&clientAddress, &size);

					if (strncmp(buffer, UNLOCK, 6) == 0) {
						unlockAnswer(buffer, dataBase, clients, unlockSocket, (struct sockaddr *)&clientAddress);
					}

					sendto(unlockSocket, buffer, MAX, 0, (struct sockaddr*)&clientAddress, size);
				} else {																				// primesc mesaj pe sockt-ul TCP
					memset(buffer, 0, MAX);
					n = recv(i, buffer, sizeof(buffer), 0);
					 
					if (n > 0) {
						printf ("Am primit de la clientul de pe socketul %d, mesajul: %s\n", i, buffer);
						answer(buffer, dataBase, clients, &activeClients, &connectedDevices, i);
						send(i, buffer, strlen(buffer), 0);						
					}
				}
			}
		}	
	}

	return 0; 
}
