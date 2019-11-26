package com.manning.apisecurityinaction.controller;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import com.manning.apisecurityinaction.token.SecureTokenStore;
import com.manning.apisecurityinaction.token.TokenStore;

import org.json.JSONObject;

import spark.Request;
import spark.Response;

import static spark.Spark.*;
 
public class TokenController {
 
    private final SecureTokenStore tokenStore;

    public TokenController(SecureTokenStore tokenStore) {
        this.tokenStore = tokenStore;
    }

    public JSONObject login(Request request, Response response) {
        String subject = request.attribute("subject");
        var expiry = Instant.now().plus(10, ChronoUnit.MINUTES);

        var token = new TokenStore.Token(subject, expiry);
        var tokenId = tokenStore.create(request, token);

        response.status(201);
        return new JSONObject().put("token", tokenId);
    }

    public void validateToken(Request request, Response response) {
     var tokenId = request.headers("Authorization");
     if (tokenId == null || !tokenId.startsWith("Bearer ")) return;
     tokenId = tokenId.substring(7);
  
     tokenStore.read(request, tokenId).ifPresent(token -> {
         if (Instant.now().isBefore(token.expiry)) {
             request.attribute("subject", token.username);
             token.attributes.forEach(request::attribute);
         } else {
             response.header("WWW-Authenticate",
                     "Bearer error=\"invalid_token\"," +
                            "error_description=\"Expired\"");
         halt(401);
         }
     });
 }
 public JSONObject logout(Request request, Response response) {
     var tokenId = request.headers("Authorization");
     if (tokenId == null || !tokenId.startsWith("Bearer ")) {
         throw new IllegalArgumentException("missing token header");
     }
     tokenId = tokenId.substring(7);
  
     tokenStore.revoke(request, tokenId);
  
     response.status(200);
     return new JSONObject();
 }
}