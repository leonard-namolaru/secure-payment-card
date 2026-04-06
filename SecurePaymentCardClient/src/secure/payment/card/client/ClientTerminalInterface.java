package secure.payment.card.client;

import java.util.Scanner;

import javax.smartcardio.CardChannel;

import com.oracle.javacard.ams.AMSession;
public class ClientTerminalInterface extends ClientUserInterface {
	Scanner scanner;
	
	public ClientTerminalInterface(Scanner scanner, CardChannel cardChannel, ServerCommunicationChannel serverCommunicationChannel, boolean debug) {
		super(cardChannel, serverCommunicationChannel, debug);
		this.scanner = scanner;
	}

	@Override
	protected void run() {
		byte[] pin;
		int userChoice;
		String capFilePath = " ";
		String propertiesFilePath = " ";
		
		do {
			System.out.println("\n");
			System.out.println("MENU");
			System.out.println("=============================================");
			System.out.println("1 - Déployer");
			System.out.println("2 - Démarrage / reprise d'une session");
			System.out.println("3 - Désinstaller");
			System.out.println("4 - Fin");
			
			System.out.print("Votre choix : ");
			userChoice = scanner.nextByte();

			switch (userChoice) {
				case 1: System.out.println("\n");
						System.out.println("DÉPLOYER");
						System.out.println("=============================================");
						if (applicationManagementService == null) {
							propertiesFilePath = getPropertiesFilePath();
							applicationManagementService = initApplicationManagementService(propertiesFilePath);
						}
						
						pin = getUserPin();
						capFilePath = getCapFilePath();
						
						String securePayementCardID = registerNewSecurePayementCard();
						if (securePayementCardID == null) {
							sendMessageToUser("Une erreur de communication avec le serveur a empêché l'enregistrement de la nouvelle carte.");
							break;
						}
						
						AMSession deployObject = createDeployObject(SecurePaymentCardClient.sAID_CAP, capFilePath, pin, securePayementCardID);
						
						sendMessageToUserIfDebug("Install");
						cardCommunicationChannel.deploy(deployObject);
						break;
						
				case 2: System.out.println("\n");
						System.out.println("DÉMARRAGE / REPRISE D'UNE SESSION");
						System.out.println("=============================================");
						if (sessionUserInterface == null) {
							startSession();
						}
						sessionUserInterface.run();
						break;
						
				case 3: System.out.println("\n");
						System.out.println("DÉSINSTALLER");
						System.out.println("=============================================");
						if (applicationManagementService == null) {
							propertiesFilePath = getPropertiesFilePath();
							applicationManagementService = initApplicationManagementService(propertiesFilePath);
						}
						
						sendMessageToUserIfDebug("Uninstall");
						sendMessageToUserIfDebug("Unload");
						cardCommunicationChannel.undeploy(applicationManagementService);
						break;
						
				case 4 : break;
				default: System.out.println("Valeur invalide");
			}
			
		} while (userChoice != 4);
		
	}

	@Override
	protected SessionUserInterface startSession() {
		sessionUserInterface = new SessionTerminalInterface(scanner, cardCommunicationChannel, serverCommunicationChannel, debug);
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
		System.out.println(message);		
	}

	@Override
	public void sendMessageToUserIfDebug(String message) {
		if (debug) {
			sendMessageToUser(message);
		}
	}
}
