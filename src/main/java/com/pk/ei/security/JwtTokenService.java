package com.pk.ei.security;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.stereotype.Component;

import com.pk.ei.domain.DomainUser;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.impl.crypto.JwtSigner;
import io.jsonwebtoken.impl.crypto.RsaProvider;
import io.jsonwebtoken.impl.crypto.RsaSigner;

@Component
public class JwtTokenService extends TokenService{

	@Value("${jwt.expiration.time}")
	private long EXPIRATION_TIME;

	@Value("${jwt.secret}")
	private String SECRET;

	@Value("${jwt.token.prefix}")
	private String TOKEN_PREFIX;

	@Value("${jwt.public.key.file}")
	private String PUB_KEY;

	@Value("${jwt.private.key.file}")
	private String PRV_KEY;

	private static final Logger logger = LoggerFactory.getLogger(JwtTokenService.class);


	public String generateNewToken(Authentication auth) {
		List<String> roles = new ArrayList<String>();
		for(GrantedAuthority role: auth.getAuthorities()){
			roles.add(role.getAuthority());
		}
		DomainUser user = (DomainUser) auth.getPrincipal();
		Claims claims = Jwts.claims().setSubject(user.getUsername());
		claims.put("roles", StringUtils.join(roles, ','));
		claims.setIssuer("Demo App");
		// HS512 signed token
		/*String token = Jwts.builder()
				.setClaims(claims)
				.setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
				.signWith(SignatureAlgorithm.HS512, SECRET)
				.compact();
		return token;*/
		// RSA signed token
		try {
			String signedToken = Jwts.builder()
					.setClaims(claims)
					.setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
					.signWith(SignatureAlgorithm.RS512, getPrivateKey())
					.compact();
			return signedToken;
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
			e.printStackTrace();
			return null;
		}
	}

	public Authentication retrieve(String token){
		Claims claims = retrieveClaims(token);
		AuthenticationWithToken authenticatedExternalWebService = 
				new AuthenticationWithToken(new DomainUser(claims.getSubject()), null, 
						AuthorityUtils.commaSeparatedStringToAuthorityList(claims.get("roles").toString()));
		return authenticatedExternalWebService;
	}

	public Claims retrieveClaims(String token){
		/*Claims claims = Jwts.parser()
				.setSigningKey(SECRET)
				.parseClaimsJws(token)
				.getBody();*/
		Claims claims = null;
		try {
			claims = Jwts.parser()
					.setSigningKey(getPublicKey())
					.parseClaimsJws(token)
					.getBody();
		} catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException | SignatureException
				| IllegalArgumentException | InvalidKeySpecException | NoSuchAlgorithmException | IOException e) {
			e.printStackTrace();
		}
		return claims;
	}

	public boolean validateToken(String authToken) {
		try {
//			Jwts.parser().setSigningKey(SECRET).parseClaimsJws(authToken);
			Jwts.parser().setSigningKey(getPublicKey()).parseClaimsJws(authToken);
			return true;
		} catch (SignatureException ex) {
			logger.error("Invalid JWT signature");
		} catch (MalformedJwtException ex) {
			logger.error("Invalid JWT token");
		} catch (ExpiredJwtException ex) {
			logger.error("Expired JWT token");
		} catch (UnsupportedJwtException ex) {
			logger.error("Unsupported JWT token");
		} catch (IllegalArgumentException ex) {
			logger.error("JWT claims string is empty.");
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}

	private PublicKey getPublicKey() throws InvalidKeySpecException, IOException, NoSuchAlgorithmException{
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		File pubKeyFile = new File(PUB_KEY);
		DataInputStream dis = null;
		byte[] pubKeyBytes = null;
		try{
			dis = new DataInputStream(new FileInputStream(pubKeyFile));
			pubKeyBytes = new byte[(int)pubKeyFile.length()];
			dis.readFully(pubKeyBytes);
			dis.close();
		}finally{
			if(dis!=null)
				dis.close();
		}

		// decode public key
		X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubKeyBytes);
		RSAPublicKey pubKey = (RSAPublicKey) keyFactory.generatePublic(pubSpec);
		return pubKey;
	}

	private RSAPrivateKey getPrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		File privKeyFile = new File(PRV_KEY);
		DataInputStream dis = null;
		byte[] privKeyBytes = null;
		try{
			dis = new DataInputStream(new FileInputStream(privKeyFile));
			privKeyBytes = new byte[(int)privKeyFile.length()];
			dis.readFully(privKeyBytes);
			dis.close();
		}finally{
			if(dis!=null)
				dis.close();
		}
		// decode private key
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privKeyBytes);
        RSAPrivateKey privKey = (RSAPrivateKey) keyFactory.generatePrivate(privSpec);
        return privKey;


	}

}
