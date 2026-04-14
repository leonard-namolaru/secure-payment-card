package secure.payment.card.client;

public class JsonPayload {
	
	public static class HttpResponseBodyUnionType<T extends AbstractJsonPayload> {
		private T expectedResponseBody;
		private ErrorResponse errorResponse;
		
		public HttpResponseBodyUnionType() {
			this.errorResponse = null;
			this.expectedResponseBody = null;
		}
		
		public boolean isError() {
			return errorResponse != null;
		}
		
		public T getExpectedResponseBody() {
			return expectedResponseBody;
		}
		
		public ErrorResponse getErrorResponse() {
			return errorResponse;
		}
		
		public void setExpectedResponseBody(T expectedResponseBody) {
			this.expectedResponseBody = expectedResponseBody;
		}
		
		public void setErrorResponse(ErrorResponse errorResponse) {
			this.errorResponse = errorResponse;
		}
	}
	
	public static class AuthenticationRequest extends AbstractJsonPayload {
		public String email;
		public String password;
		
		public AuthenticationRequest() {
			
		}
		
		public AuthenticationRequest(String email, String password) {
			this.email = email;
			this.password = password;
		}
	}
	
	public static class AuthenticationResponse extends AbstractJsonPayload {
	    public String token;
	    public String expiresIn;
	    
	    public AuthenticationResponse() {
	    	
	    }
	    
	    public AuthenticationResponse(String token, String expiresIn) {
	    	this.token = token;
	    	this.expiresIn = expiresIn;
	    }
	}
	
	public static class SecurePaymentCardRecord extends AbstractJsonPayload {
		public String publicKey;
	    public String balanceSignature;
	    
	    public SecurePaymentCardRecord() {

	    }
	    
	    public SecurePaymentCardRecord(String publicKey, String balanceSignature) {
	        this.publicKey = publicKey;
	        this.balanceSignature = balanceSignature;
	    }
	}
	
	public static class SecurePaymentCardCreationResponse extends AbstractJsonPayload {
		public String securePaymentCardId;

		public SecurePaymentCardCreationResponse() {
			
		}
		
	    public SecurePaymentCardCreationResponse(String securePaymentCardId) {
	        this.securePaymentCardId = securePaymentCardId;
	    }
	}
	
	public static class ErrorResponse extends AbstractJsonPayload {
	    public String code;
	    public String message;
	    public String description;
	    
	    public ErrorResponse() {
	    	
	    }
	    
	    public ErrorResponse(String code, String message, String description) {
	    	this.code = code;
	    	this.message = message;
	    	this.description = description;
	    }
	    
	    @Override
	    public String toString() {
	    	return String.format("%s: %s", message, description);
	    }
	}
	
	public static class OperationResult extends AbstractJsonPayload {
	    public String message;
	    
	    public OperationResult() {
	    	
	    }
	    
	    public OperationResult(String message) {
	    	this.message = message;
	    }
	    
	    public boolean isOk() {
	    	return message.equalsIgnoreCase("La mise à jour a réussi.");
	    }
	}
	
	public static class Transaction extends AbstractJsonPayload {
	    public String amount;
	    
	    public Transaction() {
	    	
	    }
	    
	    public Transaction(String amount) {
	    	this.amount = amount;
	    }
	}

	public static class UserPin extends AbstractJsonPayload {
	    public String pin;
	    
	    public UserPin() {
	    	
	    }
	    
	    public UserPin(String pin) {
	    	this.pin = pin;
	    }
	}
}
