package secure.payment.card.client;

public class HttpPayload {
	
	public static class HttpResponseBodyUnionType<T extends AbstractHttpPayload> {
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
	
	public static class AuthenticationRequest extends AbstractHttpPayload {
		public String email;
		public String password;
		
		public AuthenticationRequest() {
			
		}
		
		public AuthenticationRequest(String email, String password) {
			this.email = email;
			this.password = password;
		}
	}
	
	public static class AuthenticationResponse extends AbstractHttpPayload {
	    public String token;
	    public String expiresIn;
	    
	    public AuthenticationResponse() {
	    	
	    }
	    
	    public AuthenticationResponse(String token, String expiresIn) {
	    	this.token = token;
	    	this.expiresIn = expiresIn;
	    }
	}
	

	public static class SecurePaymentCardRecord extends AbstractHttpPayload {
		public String publicKey;
	    public String balanceSignature;
	    
	    public SecurePaymentCardRecord() {

	    }
	    
	    public SecurePaymentCardRecord(String publicKey, String balanceSignature) {
	        this.publicKey = publicKey;
	        this.balanceSignature = balanceSignature;
	    }
	}
	
	public static class SecurePaymentCardCreationResponse extends AbstractHttpPayload {
		public String securePaymentCardId;

		public SecurePaymentCardCreationResponse() {
			
		}
		
	    public SecurePaymentCardCreationResponse(String securePaymentCardId) {
	        this.securePaymentCardId = securePaymentCardId;
	    }
	}
	
	public static class ErrorResponse extends AbstractHttpPayload {
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

}
