package secure.payment.card.client;

public class SessionWebSocketInterface extends SessionUserInterface {

	public SessionWebSocketInterface(CardCommunicationChannel cardCommunicationChannel, ServerCommunicationChannel serverCommunicationChannel, boolean debug, boolean verbose) {
		super(cardCommunicationChannel, serverCommunicationChannel, debug, verbose);
	}

	@Override
	protected void run() {
		/*
		int userChoice;
		
		do {
			System.out.println("\n");
			System.out.println("MENU");
			System.out.println("=============================================");
			System.out.println("1 - Consulter le solde de la carte");
			System.out.println("2 - Débiter la carte");
			System.out.println("3 - Recharger la carte");
			System.out.println("4 - Fin");
			
			System.out.print("Votre choix : ");
			userChoice = SecurePaymentCardClient.scanner.nextByte();

			switch (userChoice) {
				case 1: System.out.println("\n");
						System.out.println("CONSULTATION DU SOLDE DE LA CARTE");
						System.out.println("=============================================");
						getBalance();
						break;
						
				case 2: System.out.println("\n");
						System.out.println("DÉBITER LA CARTE");
						System.out.println("=============================================");
						System.out.print("Montant : ");
						int debitValue = SecurePaymentCardClient.scanner.nextByte();
						debit((byte) debitValue);
						break;
						
				case 3: System.out.println("\n");
						System.out.println("RECHARGER LA CARTE");
						System.out.println("=============================================");
						System.out.print("Montant : ");
						int creditValue = SecurePaymentCardClient.scanner.nextByte();
						credit((byte) creditValue);
						break;
						
				case 4 : 
					    break;
				default: System.out.println("Valeur invalide");
			}
			
		} while (userChoice != 4);
		*/
	}

	@Override
	protected byte[] getUserPin() {
		return SecurePaymentCardClient.pin;
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
}