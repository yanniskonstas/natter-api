package com.manning.apisecurityinaction.controller;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.stream.Collectors;
  
import org.json.*;
import spark.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.dalesbred.*;

public class SpaceController {    
    
    final Logger logger = LoggerFactory.getLogger(SpaceController.class);
    private final Database database;

    public SpaceController(Database database) {
        this.database = database;
    }

    public JSONObject createSpace(Request request, Response response) {
        var json = new JSONObject(request.body());
        var spaceName = json.getString("name");        
        var owner = json.getString("owner");
        var subject = request.attribute("subject");
        
        if (spaceName.length()>255) throw new IllegalArgumentException("space name too long");
        //if (!owner.matches("[a-zA-Z][a-zA-Z0-9]{1,29}")) throw new IllegalArgumentException("invalid username: " + owner);  Don't return user input!                
        if (!owner.matches("[a-zA-Z][a-zA-Z0-9]{1,29}")) throw new IllegalArgumentException("invalid username");        
        if (!owner.equals(subject)) throw new IllegalArgumentException( "Owner must match authenticated user");                
          
        return database.withTransaction(tx -> {
            var spaceId = database.findUniqueLong("SELECT NEXT VALUE FOR space_id_seq;");
    
            database.updateUnique(
                "INSERT INTO spaces(space_id, name, owner)" +
                    " VALUES(?, ?, ?);", spaceId, spaceName, owner);
               
            database.updateUnique(
                "INSERT INTO permissions(space_id, user_id, perms) " +
                    "VALUES(?, ?, ?)", spaceId, owner, "rwd");
       
            response.status(201);
            response.header("Location", "/spaces/" + spaceId);
        
            return new JSONObject()
                .put("name", spaceName)
                .put("uri", "/spaces/" + spaceId);
        });
    }

    public JSONArray getSpaces(Request request, Response response) {
        var spaces = database.findAll(Space.class, 
            "SELECT space_id, name, owner " +
            "FROM spaces");
        response.status(200);

        return new JSONArray(spaces.stream()
        .map(Space::toJson)
        .collect(Collectors.toList()));            
    }

    public JSONObject postMessage(Request request, Response response) {
        var spaceId = Long.parseLong(request.params(":spaceId"));
        var json = new JSONObject(request.body());
        var user = json.getString("author");
        var subject = request.attribute("subject");
        var message = json.getString("message");

        if (!user.matches("[a-zA-Z][a-zA-Z0-9]{0,29}")) throw new IllegalArgumentException("invalid username");
        if (!user.equals(subject)) throw new IllegalArgumentException("author must match authenticated user");               
        if (message.length() > 1024) throw new IllegalArgumentException("message is too long");
    
        return database.withTransaction(tx -> {
            var msgId = database.findUniqueLong("SELECT NEXT VALUE FOR msg_id_seq;");
            database.updateUnique(
                "INSERT INTO messages(space_id, msg_id, msg_time," +
                    "author, msg_text) " +
                    "VALUES(?, ?, current_timestamp, ?, ?)",
                spaceId, msgId, user, message);
        
            response.status(201);
            var uri = "/spaces/" + spaceId + "/messages/" + msgId;
            response.header("Location", uri);
            return new JSONObject().put("uri", uri);
        });
      }
    
    public Message readMessage(Request request, Response response) {
        var spaceId = Long.parseLong(request.params(":spaceId"));
        var msgId = Long.parseLong(request.params(":msgId"));

        var message = database.findUnique(Message.class,
            "SELECT space_id, msg_id, author, msg_time, msg_text " +
                "FROM messages WHERE msg_id = ? AND space_id = ?",
            msgId, spaceId);

        response.status(200);
        return message;
    }

    public JSONArray findMessages(Request request, Response response) {
        var since = Instant.now().minus(1, ChronoUnit.DAYS);
        if (request.queryParams("since") != null) {
            since = Instant.parse(request.queryParams("since"));
        }
        var spaceId = Long.parseLong(request.params(":spaceId"));

        var messages = database.findAll(Long.class,
            "SELECT msg_id FROM messages " +
                "WHERE space_id = ? AND msg_time >= ?;",
            spaceId, since);

        response.status(200);
        return new JSONArray(messages.stream()
            .map(msgId -> "/spaces/" + spaceId + "/messages/" + msgId)
            .collect(Collectors.toList()));
    }

    public JSONObject addMember(Request request, Response response) {
        var json = new JSONObject(request.body());
        var spaceId = Long.parseLong(request.params(":spaceId"));
        var userToAdd = json.getString("username");
        var perms = json.getString("permissions");

        if (!perms.matches("r?w?d?")) throw new IllegalArgumentException("invalid permissions");        

        database.updateUnique(
                "INSERT INTO permissions(space_id, user_id, perms) " +
                        "VALUES(?, ?, ?)", spaceId, userToAdd, perms);

        response.status(200);
        return new JSONObject()
                .put("username", userToAdd)
                .put("permissions", perms);
    }

    public static class Message {
        private final long spaceId;
        private final long msgId;
        private final String author;
        private final Instant time;
        private final String message;

        public Message(long spaceId, long msgId, String author,
            Instant time, String message) {
            this.spaceId = spaceId;
            this.msgId = msgId;
            this.author = author;
            this.time = time;
            this.message = message;
        }
        @Override
        public String toString() {
            JSONObject msg = new JSONObject();
            msg.put("uri",
                "/spaces/" + spaceId + "/messages/" + msgId);
            msg.put("author", author);
            msg.put("time", time.toString());
            msg.put("message", message);
            return msg.toString();
        }    
    }

    public static class Space {        
        private final long space_id;
        private final String name;
        private final String owner;

        public Space(long space_id, String name, String owner) {
            this.space_id = space_id;
            this.owner = owner;
            this.name = name;
        }
        
        JSONObject toJson() {
            return new JSONObject() 
            .put("space_id", space_id)
            .put("name", name)
            .put("owner", owner);
        } 

    }
}
