package secure.payment.card.client;

import javax.smartcardio.ResponseAPDU;

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
			userChoice = SecurePaymentCardClient.scanner.nextByte();

			ResponseAPDU response;
			switch (userChoice) {
				case 1: System.out.println("\n");
						System.out.println("CONSULTATION DU SOLDE DE LA CARTE");
						System.out.println("=============================================");
						response = cardCommunicationChannel.getBalance();
						System.out.println(Util.convertResponseStatusCodeToString(response, false));
						if (response.getSW() == CardCommunicationChannel.STATUS_OK) {
							System.out.println("Signature ? " + Crypto.verifyResponseApduSignature(cardSignatureObject, response, 2));
						}
						
						byte[] balanceBytes = Crypto.getPlainTextAssociatedWithSignature(response, 2);
						System.out.println("Solde : " + Util.bytesToShort(balanceBytes));
						
						break;
						
				case 2: System.out.println("\n");
						System.out.println("DÉBITER LA CARTE");
						System.out.println("=============================================");
						System.out.print("Montant : ");
						int debitValue = SecurePaymentCardClient.scanner.nextByte();
						response = cardCommunicationChannel.debit((byte) debitValue, antiReplayAttacksCounter ,serverSignatureObject);
						antiReplayAttacksCounter++; 
						System.out.println(Util.convertResponseStatusCodeToString(response, false));
						if (response.getSW() == CardCommunicationChannel.STATUS_OK) {
							System.out.println("Signature ? " + Crypto.verifyResponseApduSignature(cardSignatureObject, response, SecurePaymentCardConstants.MONOTONIC_COUNTER_SIZE + 2));
							updateBalanceAfterDebit((byte) debitValue);
						}
						break;
						
				case 3: System.out.println("\n");
						System.out.println("RECHARGER LA CARTE");
						System.out.println("=============================================");
						System.out.print("Montant : ");
						int creditValue = SecurePaymentCardClient.scanner.nextByte();
						response = cardCommunicationChannel.credit((byte) creditValue, antiReplayAttacksCounter ,serverSignatureObject);
						antiReplayAttacksCounter++; 
						System.out.println(Util.convertResponseStatusCodeToString(response, false));
						if (response.getSW() == CardCommunicationChannel.STATUS_OK) {
							System.out.println("Signature ? " + Crypto.verifyResponseApduSignature(cardSignatureObject, response, SecurePaymentCardConstants.MONOTONIC_COUNTER_SIZE + 2));
							updateBalanceAfterCredit((byte) creditValue);
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
	
	@Override
	public void sendMessageToUserIfVerbose(String message) {
		if (verbose) {
			sendMessageToUser(message);
		}
	}

}