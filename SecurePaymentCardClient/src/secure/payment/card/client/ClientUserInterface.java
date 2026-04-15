package secure.payment.card.client;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;

import java.security.Security;
import java.security.KeyPair;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.NoSuchProviderException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;

import com.oracle.javacard.ams.AMSession;
import com.oracle.javacard.ams.AMService;
import com.oracle.javacard.ams.config.CAPFile;
import com.oracle.javacard.ams.config.GPApplicationPrivilege;
import com.oracle.javacard.ams.AMServiceFactory;

import secure.payment.card.client.JsonPayload.AuthenticationRequest;
import secure.payment.card.client.JsonPayload.AuthenticationResponse;
import secure.payment.card.client.JsonPayload.HttpResponseBodyUnionType;
import secure.payment.card.client.JsonPayload.SecurePaymentCardCreationResponse;

public abstract class ClientUserInterface implements UserInterface {
	private JavaCardClient javaCardClient;
	private AMService applicationManagementService;

	protected boolean debug;
	protected boolean verbose;
	protected SessionUserInterface sessionUserInterface;
	protected CardCommunicationChannel cardCommunicationChannel;
	protected ServerCommunicationChannel serverCommunicationChannel;

	public ClientUserInterface(String serverBaseUrl, String host, int port, boolean debug, boolean verbose) {
		this.debug = debug;
		this.verbose = verbose;
		this.serverCommunicationChannel = new ServerCommunicationChannel(serverBaseUrl, this);
		
		this.javaCardClient = new JavaCardClient(host, port, this);
		CardChannel cardChannel = javaCardClient.getCardChannel();

		sendMessageToUserIfDebug(String.format("ATR: [%s] \n", Util.convertByteArrayToString(javaCardClient.getATR())));
		
		this.sessionUserInterface = null;
		this.applicationManagementService = null;
		this.cardCommunicationChannel = new CardCommunicationChannel(cardChannel, this);
		
		AuthenticationRequest authenticationRequest = createServerAuthenticationRequestObject();
		if (authenticationRequest == null) {
			sendMessageToUser("Les informations nécessaires pour effectuer une demande "
					+ "d'authentification auprès du serveur sont introuvables.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
		}
		
		sendMessageToUserIfVerbose("Authentification auprès du serveur ...");
		HttpResponseBodyUnionType<AuthenticationResponse> httpResponse = 
				serverCommunicationChannel.authentication(authenticationRequest);
		if (!httpResponse.isError()) {
			serverCommunicationChannel.setAccessToken(httpResponse.getExpectedResponseBody().token);
			sendMessageToUserIfVerbose("L'authentification auprès du serveur a réussi.");
		} else {
			sendMessageToUser("L'authentification auprès du serveur a échoué.");
			sendMessageToUserIfDebug(httpResponse.getErrorResponse().toString());
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
		}
		
		Security.addProvider(new BouncyCastleProvider());		
	}
	
	private AMService initApplicationManagementService(String propertiesFilePath) {
		FileInputStream propertiesFile = null;
		Properties properties = new Properties();
		AMService applicationManagementService = null;
				
		try {
			propertiesFile = new FileInputStream(propertiesFilePath);
		} catch (FileNotFoundException e) {
			sendMessageToUser("Une erreur inattendue s'est produite.");
			sendMessageToUserIfDebug(String.format("initApplicationManagementService(), FileNotFoundException : %s", e.getMessage()));
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
		}
		
		try {
			properties.load(propertiesFile);
		} catch (IOException e) {
			sendMessageToUser("Une erreur inattendue s'est produite.");
			sendMessageToUserIfDebug(String.format("initApplicationManagementService(), IOException : %s", e.getMessage()));
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
		}
		
		try {
			applicationManagementService = AMServiceFactory.getInstance("GP2.2");
			applicationManagementService.setProperties(properties);
			// debugApplicationManagementService(applicationManagementService);
		} catch (NoSuchProviderException e) {
			sendMessageToUser("Une erreur inattendue s'est produite.");
			sendMessageToUserIfDebug(String.format("initApplicationManagementService(), NoSuchProviderException : %s", e.getMessage()));
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
		}
				
		return applicationManagementService;
	}
	
	private AMSession createDeployObject(String capFileAid, String capFilePath, byte[] pin, String securePayementCardID) {
		CAPFile capFile = null;
		try {
			capFile = CAPFile.from(capFilePath);
		} catch (IOException e) {
			sendMessageToUserIfDebug(String.format("createDeployObject(), IOException (1) : %s", e.getMessage()));
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
		}
		
		AMSession deploy = applicationManagementService.openSession(SecurePaymentCardClient.isdAID);  
		try {
			deploy.load(SecurePaymentCardClient.sAID_CAP, capFile.getBytes());  
		} catch (IOException e) {
			sendMessageToUser("Une erreur inattendue s'est produite.");
			sendMessageToUserIfDebug(String.format("createDeployObject(), IOException (2) : %s", e.getMessage()));
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);
		}  
				
		byte[] installationParameters = Util.concatArrays(securePayementCardID.getBytes(), pin);

		//deploy.install(SecurePaymentCardClient.sAID_CAP, SecurePaymentCardClient.sAID_AppletClass, 
		//		SecurePaymentCardClient.sAID_AppletInstance, installationParameters); 
		//deploy.close();
		return deploy;
	}
	
	private String registerNewSecurePayementCard()  {
		String securePayementCardID = null;
		
		KeyPair keyPair = Crypto.generateKeyPair();
		Signature signatureObject = Crypto.setSignatureAlgorithm();
		if (signatureObject == null) {
			sendMessageToUser("Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}

		if(!Crypto.signatureInitSign(signatureObject, (ECPrivateKey) keyPair.getPrivate())) {
			sendMessageToUser("Une erreur inattendue s'est produite.");
			System.exit(SecurePaymentCardConstants.EXIT_FAILURE);	
		}
		
		byte[] publicKey = Crypto.getByteArrayFromPublicKey((ECPublicKey) keyPair.getPublic());
		byte[] signature = Crypto.signMessage(signatureObject, new byte[] {0x00, 0x00});
		HttpResponseBodyUnionType<SecurePaymentCardCreationResponse> httpResponse = 
				serverCommunicationChannel.sendSecurePaymentCardRecord(publicKey, signature);
		
		if (!httpResponse.isError()) {
			securePayementCardID = httpResponse.getExpectedResponseBody().securePaymentCardId;
		} 		
		return securePayementCardID;
	}
	
	protected void deploy() {
		if (applicationManagementService == null) {
			String propertiesFilePath = getPropertiesFilePath();
			applicationManagementService = initApplicationManagementService(propertiesFilePath);
		}
		
		byte[] pin = getUserPin();
		String capFilePath = getCapFilePath();
		
		String securePayementCardID = registerNewSecurePayementCard();
		if (securePayementCardID == null) {
			sendMessageToUser("Une erreur de communication avec le serveur a empêché l'enregistrement de la nouvelle carte.");
			return;
		}
		sendMessageToUserIfVerbose("\n");
		sendMessageToUser(String.format("ID : %s", securePayementCardID));
		sendMessageToUser("Solde : 0");
		sendMessageToUserIfVerbose("\n");

		AMSession deployObject = createDeployObject(SecurePaymentCardClient.sAID_CAP, capFilePath, pin, securePayementCardID);
		
		sendMessageToUserIfVerbose("Démarrage de la procédure d'installation");
		setCardCertificate(deployObject, pin, securePayementCardID);
	}
	
	protected void setCardCertificate(AMSession deployObject, byte[] pin, String securePayementCardID) {
		if (applicationManagementService == null) {
			String propertiesFilePath = getPropertiesFilePath();
			applicationManagementService = initApplicationManagementService(propertiesFilePath);
		}
		
		KeyPair keyPair = Crypto.generateRsaKeyPair();
		RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
		
		byte[] modulus = rsaPrivateKey.getModulus().toByteArray();
		byte[] privateExponent = rsaPrivateKey.getPrivateExponent().toByteArray();
			
		// byte[] data = Util.concatArrays(new byte[] {(byte) 0xA2}, rsaPrivateKey.getEncoded());
		// ArrayList<CommandAPDU> commands = cardCommunicationChannel.splitPayload((byte) 0x0C, (byte) 0xE2, rsaPrivateKey.getEncoded());
		// byte[] payload = Util.concatArrays(new byte[] {0x00, 0x00, (byte) "1b45afcde9".getBytes().length}, "1b45afcde9".getBytes());

		//for (CommandAPDU command : commands) {
		//	sendMessageToUserIfDebug(Util.convertApduCommandToLogString(command));
		//	deployObject.append(command);
		//}
		
		// CommandAPDU installForPersonalization = new CommandAPDU( 0x80, 0xE2, 0b10000001, 0x00, new byte[] {});
		// deployObject.append(installForPersonalization);
		// byte[] nestedCommand = new byte[] {(byte) 0xDB, 0x7F, 0x21, 0x00, };
		// deployObject.append(installForPersonalization);
		// sendMessageToUserIfDebug(Util.convertApduCommandToLogString(installForPersonalization));
		
		// byte[] installForPersonalizationPayload = Util.concatArrays(new byte[] {0x00, 0x00, (byte) SecurePaymentCardClient.sAID_AppletInstance.getBytes().length}, 
		//		SecurePaymentCardClient.sAID_AppletInstance.getBytes());
		// CommandAPDU installForPersonalization = new CommandAPDU(0x80, 0xE6, 0b10100000, 0x00, 
		// Util.concatArrays(installForPersonalizationPayload, new byte[] {0x00, 0x00, 0x00}));
		// CommandAPDU storeDataTest = new CommandAPDU(0x80, 0xE2, 0x80, 0x00, new byte[] {0x01, 0x02, 0x03, 0x04, 0x05});

		// deployObject.append(installForPersonalization);
		// deployObject.append(storeDataTest);
		// sendMessageToUserIfDebug(Util.convertApduCommandToLogString(installForPersonalization));
		// sendMessageToUserIfDebug(Util.convertApduCommandToLogString(storeDataTest));
		
		// byte[] installToken = new byte[0];
		// GPApplicationPrivilege privilege = GPApplicationPrivilege.DEFAULT_SELECTED;
		// byte[] privileges = new byte[] {(byte)	privilege.getEncoding() };
		
		// try {
		//	ByteArrayOutputStream installCommandData = new ByteArrayOutputStream();
		//	installCommandData.write("secure.payment.card".length());
		//	installCommandData.write("secure.payment.card".getBytes());

		//	installCommandData.write("1b45afcde912646c".length());
		//	installCommandData.write("1b45afcde912646c".getBytes());

		//	installCommandData.write("1b45afcde912646c".length());
		//	installCommandData.write("1b45afcde912646c".getBytes());

		//	installCommandData.write(privileges.length);
		//	installCommandData.write(privileges);
		//	installCommandData.write(installationParameters.length);
		//	installCommandData.write(installationParameters);

		//	installCommandData.write(installToken.length);
		//	installCommandData.write(installToken);
			
		//	CommandAPDU installForInstallAndMakeSelectable = new CommandAPDU(0x80, 0xE6, 0x0C, 0x00, new byte[] {0x01, 0x02, 0x03, 0x04, 0x05});
		//  deployObject.append(installForInstallAndMakeSelectable);

			
			//deployObject.append(installForPersonalization);
		// } catch (IOException e) {
		//	System.out.println(e.getMessage());
		// }
		
		
		byte[] installationParameters = Util.concatArrays(securePayementCardID.getBytes(), pin);
		deployObject.install(SecurePaymentCardClient.sAID_CAP, SecurePaymentCardClient.sAID_AppletClass, 
				SecurePaymentCardClient.sAID_AppletInstance, installationParameters); 
		deployObject.close();
		
		List<ResponseAPDU> responses = deployObject.run(javaCardClient.getCardChannel());
		
		boolean installationOk = true;
		for(int i = 0; i < responses.size(); i++) {
			ResponseAPDU response = responses.get(i);
			sendMessageToUserIfDebug(Util.convertApduResponseToLogString(response));
			
			if (response.getSW() != CardCommunicationChannel.STATUS_OK) {
				installationOk = false;
			}
		}
		
		if (installationOk) {
			sendMessageToUserIfVerbose("Installation terminée avec succès.");
			
			cardCommunicationChannel.selectApplet();
			X509Certificate certificate = Crypto.createSelfSignedCertificate(keyPair);		
			ResponseAPDU response = cardCommunicationChannel.sendCertificate(SecurePaymentCardConstants.INS_INSTALL_CARD_CERTIFICATE, certificate);
			if (response.getSW() == CardCommunicationChannel.STATUS_OK) {
				ArrayList<CommandAPDU> commands = cardCommunicationChannel.splitPayload(SecurePaymentCardConstants.CLA_SECURE_PAYMENT_CARD, 
						SecurePaymentCardConstants.INS_INSTALL_CARD_CERTIFICATE, privateExponent, (byte) 0x01);
				response = cardCommunicationChannel.sendCommands(commands);
				if (response.getSW() == CardCommunicationChannel.STATUS_OK) {
					if (modulus[0] == 0x00) {
						byte[] buffer = new byte[modulus.length - 1];
						System.arraycopy(modulus, 1, buffer, 0, buffer.length);
						modulus = buffer;
					}
					
					commands = cardCommunicationChannel.splitPayload(SecurePaymentCardConstants.CLA_SECURE_PAYMENT_CARD, 
							SecurePaymentCardConstants.INS_INSTALL_CARD_CERTIFICATE, modulus, (byte) 0x02);
					response = cardCommunicationChannel.sendCommands(commands);
				}
			} 
		} else {
			sendMessageToUser("L'installation a échoué.");
		}
	}
	
	protected void startOrResumeSession() {
		if (sessionUserInterface == null) {
			startSession();
		}
		sessionUserInterface.run();
	}
	
	protected void uninstall() {
		if (applicationManagementService == null) {
			String propertiesFilePath = getPropertiesFilePath();
			applicationManagementService = initApplicationManagementService(propertiesFilePath);
		}
		
		sendMessageToUserIfDebug("Uninstall");
		sendMessageToUserIfDebug("Unload");
		cardCommunicationChannel.undeploy(applicationManagementService);
		sessionUserInterface = null;
	}
	
	protected void disconnect() {
		javaCardClient.disconnect();
	}
	
	protected abstract void run();
	protected abstract byte[] getUserPin();
	protected abstract String getCapFilePath();
	protected abstract String getPropertiesFilePath();
	protected abstract SessionUserInterface startSession();
	public abstract void sendMessageToUser(String message);
	public abstract void sendMessageToUserIfDebug(String message);
	public abstract void sendMessageToUserIfVerbose(String message);
	protected abstract AuthenticationRequest createServerAuthenticationRequestObject();
}
