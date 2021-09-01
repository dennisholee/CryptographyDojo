package io.forest;

import java.security.NoSuchAlgorithmException;

public interface ICryptoSpecBuilder {

	ICryptoSpec build() throws NoSuchAlgorithmException;
	
}
