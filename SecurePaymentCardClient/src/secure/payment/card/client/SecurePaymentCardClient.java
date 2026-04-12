package secure.payment.card.client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.UnknownHostException;
import java.util.Scanner;

public class SecurePaymentCardClient {
	public static final Scanner scanner = new Scanner(System.in); 		
	public static WebSocketCommunicationChannel webSocketCommunicationChannel = null;

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
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	    
		/*
		ClientTerminalInterface clientTerminalInterface = new ClientTerminalInterface(BASE_URL, HOST, PORT, DEBUG, VERBOSE);
		clientTerminalInterface.run();
		*/	
		scanner.close();	
		System.exit(SecurePaymentCardConstants.EXIT_SUCCESS);
	}
}