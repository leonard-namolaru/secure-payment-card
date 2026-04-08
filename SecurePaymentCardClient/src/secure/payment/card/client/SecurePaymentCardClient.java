package secure.payment.card.client;

import java.util.Scanner;

public class SecurePaymentCardClient {
	public static final Scanner scanner = new Scanner(System.in); 		
	
	public static final String sAID_CAP = "aid:1b45afcde9";
	public static final String isdAID = "aid:A000000151000000";
	public static final String sAID_AppletClass = "aid:1b45afcde912646c";
	public static final String sAID_AppletInstance = "aid:1b45afcde912646c";
	
	public static String[] cmdArgs;
	public static byte[] pin = new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
			
	/**
	 * @param args Arguments de ligne de commande. {@code -cap=<capfile> -props=<propsfile>}
	 */
	public static void main(String[] args) {
		final String BASE_URL = "http://localhost:8080";
		final String HOST = "localhost";
		final boolean VERBOSE = true;
		final boolean DEBUG = true;
		final int PORT = 9025;
	
		cmdArgs = args;

		ClientTerminalInterface clientTerminalInterface = new ClientTerminalInterface(BASE_URL, HOST, PORT, DEBUG, VERBOSE);
		clientTerminalInterface.run();
				
		scanner.close();	
		System.exit(SecurePaymentCardConstants.EXIT_SUCCESS);
	}
}