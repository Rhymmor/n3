const net = require('net'); // Enables to start the server
const fs = require('fs'); // Enables to load the certificate keys
const POP3Server = require('./pop3Server').POP3Server;
const sasl_methods = require("./sasl").AUTHMethods; // Extensions to the SASL-AUTH
/**
 * N3
 * 
 * POP3 Server for Node.JS
 * 
 * Usage:
 *     N3.startServer(port, server_name, AuthStore, MessageStore);
 *     - port (Number): Port nr to listen, 110 for unencrypted POP3
 *     - server_name (String): server domain name, ie. "node.ee"
 *     - AuthStore (Function): Function to authenticate users, see pop3_server.js for example
 *     - MessageStore (Constructor): See messagestore.js or pop3_server.js for example
 * 
 **/
var N3 = {
    
    /**
     * N3.server_name -> String
     * 
     * Domain name of the server. Not really important, mainly used for generating
     * unique tokens (ie: <unique_str@server_name>) and for logging
     **/
    server_name: "localhost",
    
    /**
     * N3.States -> Object
     * 
     * Constants for different states of the current connection. Every state has
     * different possibilities, ie. APOP is allowed only in AUTHENTICATION state
     **/
    States:{
        AUTHENTICATION: 1,
        TRANSACTION:2,
        UPDATE: 3
    },

    /**
     * N3.COUNTER -> Number
     * 
     * Connection counter, every time a new connection to the server is made, this
     * number is incremented by 1. Useful for generating connection based unique tokens
     **/
    COUNTER: 0,
    
    /**
     * N3.authMethods -> Object
     * 
     * Houses different authentication methods for SASL-AUTH as extensions. See
     * N3.extendAuth for additional information 
     **/
    authMethods: {},
    
    /**
     * N3.capabilities -> Object
     * 
     * Prototype object for individual servers. Contains the items that will
     * be listed as an answer to the CAPA command. Individual server will add
     * specific commands to the list by itself.
     **/
    capabilities: {
        // AUTHENTICATION
        1: ["UIDL", "USER", "RESP-CODES", "AUTH-RESP-CODE"],
        // TRANSACTION
        2: ["UIDL", "EXPIRE NEVER", "LOGIN-DELAY 0", "IMPLEMENTATION N3 node.js POP3 server"],
        // UPDATE
        3: []
    },

    /**
     * N3.connected_users -> Object
     * 
     * Keeps a list of all users that currently have a connection. Users are added
     * as keys with a value of TRUE to the list and deleted when disconnecting
     * 
     * Login:
     *     N3.connected_users[username] = true;
     * Logout:
     *     delete N3.connected_users[username]
     * Check state:
     *     if(N3.connected_users[username]);
     **/
    connected_users:{},
    
    /**
     * N3.startServer(port, server_name, AuthStore, MessageStore) -> Boolean
     * - port (Number): Port nr to listen, 110 for unencrypted POP3
     * - server_name (String): server domain name, ie. "node.ee"
     * - AuthStore (Function): Function to authenticate users, see pop3_server.js for example
     * - MessageStore (Constructor): See messagestore.js or pop3_server.js for example
     * 
     * Creates a N3 server running on specified port.
     **/
    startServer: function(server_name, auth, MsgStore, callback){
        
        // try to start the server
        return net.createServer(this.createInstance.bind(
            this, server_name, auth, MsgStore)
        );

    },
    
    /**
     * N3.createInstance(server_name, auth, MsgStore, socket) -> Object
     * 
     * Creates a dedicated server instance for every separate connection. Run by
     * net.createServer after a user tries to connect to the selected port.
     **/
    createInstance: function(server_name, auth, MsgStore, socket){
        new this.POP3Server(socket, server_name, auth, MsgStore, N3);
    },
    
    /**
     * N3.extendAUTH(name, action) -> undefined
     * - name (String): name for the authentication method, will be listed with SASL
     * - action (Function): Validates the authentication of an user
     * 
     * Enables extending the SALS AUTH by adding new authentication method.
     * action gets a parameter authObject and is expected to return TRUE or FALSE
     * to show if the validation succeeded or not.
     * 
     * authObject has the following structure:
     *   - wait (Boolean): initially false. If set to TRUE, then the next response from
     *                     the client will be forwarded directly back to the function
     *   - user (String): initially false. Set this value with the user name of the logging user
     *   - params (String): Authentication parameters from the client
     *   - history (Array): an array of previous params if .wait was set to TRUE
     *   - n3 (Object): current session object
     *   - check (Function): function to validate the user, has two params:
     *     - user (String): username of the logging user
     *     - pass (Function | String): password or function(pass){return pass==pass}
     * 
     * See sasl.js for some examples
     **/
    extendAUTH: function(name, action){
        name = name.trim().toUpperCase();
        this.authMethods[name] = action;
    }
}

N3.POP3Server = POP3Server;

// Add extensions from auth_pop3.js

for(var i=0, len=sasl_methods.length; i < len; i++){
    N3.extendAUTH(sasl_methods[i].name, sasl_methods[i].fn);
}

// EXPORT
this.N3 = N3;

