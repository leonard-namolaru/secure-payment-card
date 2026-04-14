package secure.payment.card.client;

import java.util.Scanner;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.UnknownHostException;

public class SecurePaymentCardClient {
	public static String[] cmdArgs;
	public static final Scanner scanner = new Scanner(System.in); 		
	public static WebSocketCommunicationChannel webSocketCommunicationChannel = null;

	public static final String sAID_CAP = "aid:1b45afcde9";
	public static final String isdAID = "aid:A000000151000000";
	public static final String sAID_AppletClass = "aid:1b45afcde912646c";
	public static final String sAID_AppletInstance = "aid:1b45afcde912646c";
	
	/**
	 * @param args Arguments de ligne de commande. {@code -mode=<terminal|gui> -cap=<capfile> -props=<propsfile>}
	 */
	public static void main(String[] args) {
		final String BASE_URL = "http://localhost:8080";
		final String HOST = "localhost";
		final int PORT = 9025;
		
		final boolean DEBUG = true;
		final boolean VERBOSE = true;
		final boolean TERMINAL = false;
		cmdArgs = args;
		
		if (TERMINAL) {
			ClientTerminalInterface clientTerminalInterface = new ClientTerminalInterface(BASE_URL, HOST, PORT, DEBUG, VERBOSE);
			clientTerminalInterface.run();
		} else {
			try {
				webSocketCommunicationChannel = new WebSocketCommunicationChannel(BASE_URL, HOST, PORT, DEBUG, VERBOSE, 80);
			    webSocketCommunicationChannel.start();

			    BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));
			    while (true) {
			      String in = null;
				  try {
					in = bufferedReader.readLine();
					System.out.print(in);
				  } catch (IOException e) {
					e.printStackTrace();
				  }
				  
			      webSocketCommunicationChannel.broadcast(in);
			      if (in.equals("exit")) {
			        try {
						webSocketCommunicationChannel.stop(1000);
					} catch (InterruptedException e) {
						e.printStackTrace();
					}
			        break;
			      }
			    }		
			} catch (UnknownHostException e) {
				e.printStackTrace();
			}
		}
	    
		scanner.close();	
		System.exit(SecurePaymentCardConstants.EXIT_SUCCESS);
	}
}