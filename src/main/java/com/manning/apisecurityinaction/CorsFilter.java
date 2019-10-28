package com.manning.apisecurityinaction;
  
 import spark.*;
 import java.util.*;
 import static spark.Spark.*;
  
 class CorsFilter implements Filter {
   private final Set<String> allowedOrigins;
  
   CorsFilter(Set<String> allowedOrigins) {
     this.allowedOrigins = allowedOrigins;
   }
  
   @Override
   public void handle(Request request, Response response) {
       var origin = request.headers("Origin");
       if (origin != null && allowedOrigins.contains(origin)) {
           response.header("Access-Control-Allow-Origin", origin);
           response.header("Vary", "Origin");
       }
    
       if (isPreflightRequest(request)) {
           if (origin == null || !allowedOrigins.contains(origin)) {
               halt(403);
           }
    
           response.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
           response.header("Access-Control-Allow-Methods", "GET, POST, DELETE");
           halt(204);
       }
   }
  
   private boolean isPreflightRequest(Request request) {
     return "OPTIONS".equals(request.requestMethod()) &&
       request.headers().contains("Access-Control-Request-Method");
   }
 }