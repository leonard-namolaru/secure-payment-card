package secure.payment.card.client;

import java.util.Scanner;
import javax.smartcardio.ResponseAPDU;

public class SessionTerminalInterface extends SessionUserInterface {
	Scanner scanner;

	public SessionTerminalInterface(Scanner scanner, CardCommunicationChannel cardCommunicationChannel, ServerCommunicationChannel serverCommunicationChannel, boolean debug) {
		super(cardCommunicationChannel, serverCommunicationChannel, debug);
		this.scanner = scanner;
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
			userChoice = scanner.nextByte();

			ResponseAPDU response;
			switch (userChoice) {
				case 1: System.out.println("\n");
						System.out.println("CONSULTATION DU SOLDE DE LA CARTE");
						System.out.println("=============================================");
						response = cardCommunicationChannel.getBalance();
						System.out.println(Util.convertResponseStatusCodeToString(response, false));
						if (response.getSW() == CardCommunicationChannel.STATUS_OK) {
							System.out.println("Signature ? " + Crypto.verifySignature(cardSignatureObject, response, 2));
						}
						break;
						
				case 2: System.out.println("\n");
						System.out.println("DÉBITER LA CARTE");
						System.out.println("=============================================");
						System.out.print("Montant : ");
						int debitValue = scanner.nextByte();
						response = cardCommunicationChannel.debit((byte) debitValue, antiReplayAttacksCounter ,serverSignatureObject);
						antiReplayAttacksCounter++; 
						System.out.println(Util.convertResponseStatusCodeToString(response, false));
						if (response.getSW() == CardCommunicationChannel.STATUS_OK) {
							System.out.println("Signature ? " + Crypto.verifySignature(cardSignatureObject, response, SecurePaymentCardConstants.MONOTONIC_COUNTER_SIZE + 2));
						}
						break;
						
				case 3: System.out.println("\n");
						System.out.println("RECHARGER LA CARTE");
						System.out.println("=============================================");
						System.out.print("Montant : ");
						int creditValue = scanner.nextByte();
						response = cardCommunicationChannel.credit((byte) creditValue, antiReplayAttacksCounter ,serverSignatureObject);
						antiReplayAttacksCounter++; 
						System.out.println(Util.convertResponseStatusCodeToString(response, false));
						if (response.getSW() == CardCommunicationChannel.STATUS_OK) {
							System.out.println("Signature ? " + Crypto.verifySignature(cardSignatureObject, response, SecurePaymentCardConstants.MONOTONIC_COUNTER_SIZE + 2));
						}
						break;
						
				case 4 : System.out.println(".");
						 break;
				default: System.out.println("Valeur invalide");
			}
			
		} while (userChoice != 4);
	}

	@Override
	protected byte[] getUserPin() {
		return SecurePaymentCardClient.pin;
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
}