package com.manning.apisecurityinaction;

import com.manning.apisecurityinaction.controller.*;
import com.manning.apisecurityinaction.token.*; 

import org.h2.jdbcx.*;
import org.json.*;
import java.nio.file.*;
import java.sql.*;
import org.dalesbred.*;
import org.dalesbred.result.*;
import com.google.common.util.concurrent.*;
import spark.Request;
import spark.Response;
import spark.embeddedserver.EmbeddedServers;
import spark.embeddedserver.jetty.EmbeddedJettyFactory; 

import static spark.Spark.*;
  
public class Main {
  
public static void main(String... args) throws Exception {
  // Avoid CORS 
  staticFiles.location("/public");

  // Use TLS
  secure("localhost.p12", "changeit", null, null);

  // Secuting Cookie
  EmbeddedServers.add(EmbeddedServers.defaultIdentifier(), new EmbeddedJettyFactory().withHttpOnly(true));

  // Start up the connection pool using the root DDL user and then connect by using a DML user 
  var datasource = JdbcConnectionPool.create("jdbc:h2:mem:natter", "natter", "password");
  createTables(datasource.getConnection());
  datasource = JdbcConnectionPool.create("jdbc:h2:mem:natter", "natter_api_user", "password");  
  var database = Database.forDataSource(datasource);  

  // Create the controllers
  TokenStore tokenStore = new CookieTokenStore();
  var tokenController = new TokenController(tokenStore);
  var userController = new UserController(database);
  var spaceController = new SpaceController(database);    
  var auditController = new AuditController(database);  
  var moderatorController = new ModeratorController(database);

  // Rate limiting
  var rateLimiter = RateLimiter.create(2.0d);  
  before((request, response) -> {
    if (!rateLimiter.tryAcquire()) {
      halt(429);
    }
  });    

  // Spark - Before checks
  before(((request, response) -> { //Request should be JSON olnly to avoid injections etc
    if (request.requestMethod().equals("POST") && !"application/json".equals(request.contentType())) {
      halt(406, new JSONObject().put("error", "Only application/json supported").toString());
    }
  }));  

  // Authentication  
  before(userController::authenticate);  
  before(tokenController::validateToken);
  
  // Audit Log     
  before(auditController::auditRequestStart);
  afterAfter(auditController::auditRequestEnd);
  get("/logs", auditController::readAuditLog);
  
  // Access control - Authorization
  before("/sessions", userController::requireAuthentication);  
  before("/spaces", userController::requireAuthentication);  
  before("/spaces/:spaceId/messages", userController.requirePermission("POST", "w"));
  before("/spaces/:spaceId/messages/*", userController.requirePermission("GET", "r"));
  before("/spaces/:spaceId/messages", userController.requirePermission("GET", "r"));
  before("/spaces/:spaceId/messages/*", userController.requirePermission("DELETE", "d"));
  before("/spaces/:spaceId/members", userController.requirePermission("POST", "rwd"));    
  
  // Application logic - Routing
  post("/users", userController::registerUser);  
  post("/spaces", spaceController::createSpace);   
  post("/spaces/:spaceId/messages", spaceController::postMessage);
  post("/spaces/:spaceId/members", spaceController::addMember);
  post("/sessions", tokenController::login);
  get("/spaces", spaceController::getSpaces);
  get("/spaces/:spaceId/messages/:msgId", spaceController::readMessage);
  get("/spaces/:spaceId/messages", spaceController::findMessages);
  delete("/spaces/:spaceId/messages/:msgId", moderatorController::deletePost);  
  delete("/sessions", tokenController::logout);  

  // Spark - After checks
  //after((request, response) -> {response.type("application/json");});  
 
  // Spark - After after checks
  afterAfter((request, response) -> {
    response.type("application/json");
    response.header("X-Content-Type-Options", "nosniff");
    response.header("X-XSS-Protection", "1; mode=block");
    response.header("Cache-Control", "private, max-age=0");
    response.header("Strict-Transport-Security", "max-age=31536000");
    response.header("Server", "");    
  });  

  //afterAfter((request, response) -> {response.header("X-XSS-Protection", "0");}); //omit XSS Protection
  
  // Spark - Error handling
  internalServerError(new JSONObject().put("error", "internal server error").toString());
  notFound(new JSONObject().put("error", "not found").toString()); 
  
  // Spark - Exception handling
  exception(IllegalArgumentException.class,  Main::badRequest);
  exception(JSONException.class, Main::badRequest);   
  exception(EmptyResultException.class, (e, request, response) -> response.status(404));
  }

  private static void badRequest(Exception ex, Request request, Response response) {
    response.status(400);
    response.body("{\"error\": \"" + ex.getMessage() + "\"}"); //Don't expose all the details of the exception
  }  

  private static void createTables(Connection connection) throws Exception {
    try (var conn = connection;
        var stmt = conn.createStatement()) {
      conn.setAutoCommit(false);
      Path path = Paths.get(Main.class.getResource("/schema.sql").toURI());
      stmt.execute(Files.readString(path));
      conn.commit();
    }
  }
}

//curl -i -u demo:password -d '{"name":"test space","owner":"demo"}' -H 'Content-Type: application/json' http://localhost:4567/spaces