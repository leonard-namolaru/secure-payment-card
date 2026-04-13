package secure.payment.card.client;

import secure.payment.card.client.JsonPayload.AuthenticationRequest;

public class ClientWebSocketInterface extends ClientUserInterface {	

	public ClientWebSocketInterface(String serverBaseUrl, String host, int port, boolean debug, boolean verbose) {
		super(serverBaseUrl, host, port, debug, verbose);
	}

	@Override
	protected void run() {
		
		
		
		
		//disconnect();
    }

		/**
		int userChoice;
		do {
			System.out.println("\n");
			System.out.println("MENU");
			System.out.println("=============================================");
			System.out.println("1 - Déployer");
			System.out.println("2 - Démarrage / reprise d'une session");
			System.out.println("3 - Désinstaller");
			System.out.println("4 - Fin");
			
			System.out.print("Votre choix : ");
			userChoice = SecurePaymentCardClient.scanner.nextByte();

			switch (userChoice) {
				case 1: System.out.println("\n");
						System.out.println("DÉPLOYER");
						System.out.println("=============================================");
						deploy();
						break;
						
				case 2: System.out.println("\n");
						System.out.println("DÉMARRAGE / REPRISE D'UNE SESSION");
						System.out.println("=============================================");
						startOrResumeSession();
						break;
						
				case 3: System.out.println("\n");
						System.out.println("DÉSINSTALLER");
						System.out.println("=============================================");
						uninstall();
						break;
						
				case 4 : break;
				default: System.out.println("Valeur invalide");
			}
			
		} while (userChoice != 4);
		*/
		/*
		disconnect();
	}
	*/

	@Override
	protected SessionUserInterface startSession() {
		sessionUserInterface = new SessionWebSocketInterface(cardCommunicationChannel, serverCommunicationChannel, debug, verbose);
		return sessionUserInterface;
	}

	@Override
	protected byte[] getUserPin() {
		return SecurePaymentCardClient.pin;
	}

	@Override
	protected String getCapFilePath() {
		return Util.getArg(SecurePaymentCardClient.cmdArgs, "cap", "");
	}

	@Override
	protected String getPropertiesFilePath() {
		return Util.getArg(SecurePaymentCardClient.cmdArgs, "props", "");
	}
	
	@Override
	public void sendMessageToUser(String message) {
		if (message.trim().equals("\n")) {
			return;
		}
		
		if (SecurePaymentCardClient.webSocketCommunicationChannel != null) {
			System.out.println(message);		
			SecurePaymentCardClient.webSocketCommunicationChannel.broadcast(message);
		} else {
			System.out.println(message);		
		}
	}

	@Override
	public void sendMessageToUserIfDebug(String message) {
		if (debug) {
			System.out.println(message);
		}
	}
	
	@Override
	public void sendMessageToUserIfVerbose(String message) {
		if (verbose) {
			sendMessageToUser(message);
		}
	}

	@Override
	protected AuthenticationRequest createServerAuthenticationRequestObject() {
		AuthenticationRequest authenticationRequest = SecurePaymentCardClient.webSocketCommunicationChannel.authenticationRequest;
		if (authenticationRequest == null) {
			sendMessageToUser("Il est obligatoire de saisir une adresse mail et "
					+ "un mot de passe pour s'authentifier auprès du serveur.");
			return new AuthenticationRequest("", "");
		}
		
		return authenticationRequest;
	}
}