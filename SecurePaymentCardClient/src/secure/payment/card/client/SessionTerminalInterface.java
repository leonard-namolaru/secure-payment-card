package secure.payment.card.client;

import java.util.InputMismatchException;

public class SessionTerminalInterface extends SessionUserInterface {

	public SessionTerminalInterface(CardCommunicationChannel cardCommunicationChannel, ServerCommunicationChannel serverCommunicationChannel, boolean debug, boolean verbose) {
		super(cardCommunicationChannel, serverCommunicationChannel, debug, verbose);
	}

	@Override
	protected void run() {
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
			try {
				userChoice = SecurePaymentCardClient.scanner.nextByte();
			} catch (InputMismatchException e) {
				userChoice = 5;
			}
			
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
						try {
							int debitValue = SecurePaymentCardClient.scanner.nextByte();						
							debit((byte) debitValue);
						} catch (InputMismatchException e) {
							System.out.println("Valeur invalide");
						}
						break;
						
				case 3: System.out.println("\n");
						System.out.println("RECHARGER LA CARTE");
						System.out.println("=============================================");
						System.out.print("Montant : ");
						try {
							int creditValue = SecurePaymentCardClient.scanner.nextByte();
							credit((byte) creditValue);
						} catch (InputMismatchException e) {
							System.out.println("Valeur invalide");
						}
						break;
						
				case 4 : 
					    break;
				default: System.out.println("Valeur invalide");
			}
			
		} while (userChoice != 4);
	}

	@Override
	protected byte[] getUserPin() {
		byte[] pin = new byte[SecurePaymentCardConstants.PIN_SIZE];
		
		System.out.println("Code PIN : ");
		for(int i = 0; i < SecurePaymentCardConstants.PIN_SIZE; i++) {
			System.out.print("# : ");
			
			boolean inputOk = false;
			while (!inputOk) {
				try {
					int input = SecurePaymentCardClient.scanner.nextByte();
					pin[i] = (byte) input;
					inputOk = true;
				} catch (InputMismatchException e) {
					System.out.println("Valeur invalide");
				}
			}
		}
		
		return pin;
	}

	@Override
	public void sendMessageToUser(String message) {
		System.out.println(message);		
	}

	@Override
	public void sendMessageToUserIfDebug(String message) {
		if (debug) {
			sendMessageToUser(message);
		}
	}
	
	@Override
	public void sendMessageToUserIfVerbose(String message) {
		if (verbose) {
			sendMessageToUser(message);
		}
	}
}