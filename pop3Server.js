const crypto = require('crypto');
/**
 * new POP3Server(socket, server_name, auth, MsgStore, N3)
 * 
 * Creates a dedicated server instance for every separate connection. Run by
 * this.N3.createInstance after a user tries to connect to the selected port.
 **/
function POP3Server(socket, server_name, auth, MsgStore, N3){
    this.N3 = N3;
    this.server_name = server_name || this.N3.server_name;
    this.socket   = socket;
    this.state    = this.N3.States.AUTHENTICATION;
    this.connection_id = ++this.N3.COUNTER;
    this.UID      = this.connection_id + "." + (+new Date());
    this.authCallback = auth;
    this.MsgStore = MsgStore;
    this.connection_secured = false;

    // Copy this.N3 capabilities info into the current object
    this.capabilities = {
        1: Object.create(this.N3.capabilities[1]),
        2: Object.create(this.N3.capabilities[2]),
        3: Object.create(this.N3.capabilities[3])
    }
    
    //console.log("New connection from "+socket.remoteAddress);
    this.response("+OK POP3 Server ready <"+this.UID+"@"+this.server_name+">");
    
    socket.on("data", this.onData.bind(this));
    socket.on("end", this.onEnd.bind(this));
}
 
/**
 * POP3Server#destroy() -> undefined
 * 
 * Clears the used variables just in case (garbage collector should
 * do this by itself)
 **/
POP3Server.prototype.destroy = function(){
    if(this.timer)clearTimeout(this.timer);
    this.timer = null;
    this.socket = null;
    this.state = null;
    this.authCallback = null;
    this.user = null;
    this.MsgStore = null;
}

POP3Server.prototype._updateTimeout = function() {
    if(!this.socket)
        return;
    if(this.state==this.N3.States.TRANSACTION)
        this.state = this.N3.States.UPDATE;
    if(this.user && this.N3.connected_users[this.user.trim().toLowerCase()])
        delete this.N3.connected_users[this.user.trim().toLowerCase()];
    this.socket.end();
    this.destroy();
};
/**
 * 
 **/
// kill client after 10 min on inactivity
POP3Server.prototype.updateTimeout = function(){
    if(this.timer)clearTimeout(this.timer);
    this.timer = setTimeout(this._updateTimeout, 10*60*1000); 
}

POP3Server.prototype.response = function(message){
    var response;
    if(typeof message == "string"){
        response = new Buffer(message + "\r\n", "utf-8");
    }else{
        response = Buffer.concat([message, new Buffer("\r\n", "utf-8")]);
    }
    
    //console.log("SERVER: "+message);
    this.socket.write(response);
}

POP3Server.prototype.afterLogin = function(){
    var messages = false;

    if(this.user && this.N3.connected_users[this.user.trim().toLowerCase()]){
        this.user = false; // to prevent clearing it with exit
        return "-ERR [IN-USE] You already have a POP session running";
    }

    if(typeof this.MsgStore!="function")
        return false;
    
    if(this.user && (messages = new this.MsgStore(this.user))){
        this.messages = messages;
        this.N3.connected_users[this.user.trim().toLowerCase()] = true;
        return true;
    }
    return false;
}

POP3Server.prototype.onData = function(data){
    var request = data.toString("ascii", 0, data.length);
    //console.log("CLIENT: "+request.trim());
    this.onCommand(request);
}

POP3Server.prototype.onEnd = function(data){
    if(this.state===null)
        return;
    this.state = this.N3.States.UPDATE;
    if(this.user){
        //console.log("Closing: "+this.user)
    }
    if(this.user && this.N3.connected_users[this.user.trim().toLowerCase()])
        delete this.N3.connected_users[this.user.trim().toLowerCase()];
    //console.log("Connection closed\n\n");
    this.socket.end();
    this.destroy();
}

POP3Server.prototype.onCommand = function(request){
    var cmd = request.match(/^[A-Za-z]+/),
        params = cmd && request.substr(cmd[0].length+1);

    this.updateTimeout();

    if(this.authState){
        params = request.trim();
        return this.cmdAUTHNext(params);
    }
    
    if(!cmd)
        return this.response("-ERR");
    if(typeof this["cmd"+cmd[0].toUpperCase()]=="function"){
        return this["cmd"+cmd[0].toUpperCase()](params && params.trim());
    }
    
    return this.response("-ERR");
}

// Universal commands
    
// CAPA - Reveals server capabilities to the client
POP3Server.prototype.cmdCAPA = function(params){

    if(params && params.length){
        return this.response("-ERR Try: CAPA");
    }

    params = (params || "").split(" ");
    this.response("+OK Capability list follows");
    for(var i=0;i<this.capabilities[this.state].length; i++){
        this.response(this.capabilities[this.state][i]);
    }
    if(this.N3.authMethods){
        var methods = [];
        for(var i in this.N3.authMethods){
            if(this.N3.authMethods.hasOwnProperty(i))
                methods.push(i);
        }
        if(methods.length && this.state==this.N3.States.AUTHENTICATION)
            this.response("SASL "+methods.join(" "));
    }
    this.response(".");
}

// QUIT - Closes the connection
POP3Server.prototype.cmdQUIT = function(){
    if(this.state==this.N3.States.TRANSACTION){
        this.state = this.N3.States.UPDATE;
        this.messages.removeDeleted();
    }
    this.response("+OK this.N3 POP3 Server signing off");
    this.socket.end();
}

// AUTHENTICATION commands

// AUTH auth_engine - initiates an authentication request
POP3Server.prototype.cmdAUTH = function(auth){
    if(this.state!=this.N3.States.AUTHENTICATION) return this.response("-ERR Only allowed in authentication mode");
    
    if(!auth)
        return this.response("-ERR Invalid authentication method");
    
    var parts = auth.split(" "),
        method = parts.shift().toUpperCase().trim(),
        params = parts.join(" "),
        response;
    
    this.authObj = {wait: false, params: params, history:[], check: this.cmdAUTHCheck.bind(this), N3: this.N3};
    
    // check if the asked auth methid exists and if so, then run it for the first time
    if(typeof this.N3.authMethods[method]=="function"){
        response = this.N3.authMethods[method](this.authObj);
        if(response){
            if(this.authObj.wait){
                this.authState = method;
                this.authObj.history.push(params);
            }else if(response===true){
                response = this.cmdDoAUTH();
            }
            this.response(response);
        }else{
            this.authObj = false;
            this.response("-ERR [AUTH] Invalid authentication");
        }
    }else{
        this.authObj = false;
        this.response("-ERR Unrecognized authentication type");
    }
}

POP3Server.prototype.cmdDoAUTH = function(){
    var response;
    this.user = this.authObj.user;
    if((response = this.afterLogin())===true){
        this.state = this.N3.States.TRANSACTION;
        response = "+OK You are now logged in";
    }else{
        response = response || "-ERR [SYS] Error with initializing";
    }
    this.authState = false;
    this.authObj = false;
    return response;
}

POP3Server.prototype.cmdAUTHNext = function(params){
    if(this.state!=this.N3.States.AUTHENTICATION) return this.response("-ERR Only allowed in authentication mode");
    this.authObj.wait = false;
    this.authObj.params = params;
    this.authObj.N3 = this.N3;
    var response = this.N3.authMethods[this.authState](this.authObj);
    if(!response){
        this.authState = false;
        this.authObj = false;
        return this.response("-ERR [AUTH] Invalid authentication");
    }
    if(this.authObj.wait){
        this.authObj.history.push(params);
    }else if(response===true){
        response = this.cmdDoAUTH();
    }
    this.response(response);
}

POP3Server.prototype.cmdAUTHCheck = function(user, passFn){
    if(user) this.authObj.user = user;
    if(typeof this.authCallback=="function"){
        if(typeof passFn=="function")
            return !!this.authCallback(user, passFn);
        else if(typeof passFn=="string" || typeof passFn=="number")
            return !!this.authCallback(user, function(pass){return pass==passFn});
        else return false;
    }
    return true;
}

// APOP username hash - Performs an APOP authentication
// http://www.faqs.org/rfcs/rfc1939.html #7

// USAGE:
//   CLIENT: APOP user MD5(salt+pass)
//   SERVER: +OK You are now logged in

POP3Server.prototype.cmdAPOP = function(params){
    if(this.state!=this.N3.States.AUTHENTICATION) return this.response("-ERR Only allowed in authentication mode");
    
    params = params.split(" ");
    var user = params[0] && params[0].trim(),
        hash = params[1] && params[1].trim().toLowerCase(),
        salt = "<"+this.UID+"@"+this.server_name+">",
        response;

    if(typeof this.authCallback=="function"){
        if(!this.authCallback(user, function(pass){
            return md5(salt+pass)==hash;
        })){
            return this.response("-ERR [AUTH] Invalid login");
        }
    }
    
    this.user = user;
    
    if((response = this.afterLogin())===true){
        this.state = this.N3.States.TRANSACTION;
        return this.response("+OK You are now logged in");
    }else
        return this.response(response || "-ERR [SYS] Error with initializing");
}

// USER username - Performs basic authentication, PASS follows
POP3Server.prototype.cmdUSER = function(username){
    if(this.state!=this.N3.States.AUTHENTICATION) return this.response("-ERR Only allowed in authentication mode");

    this.user = username.trim();
    if(!this.user)
        return this.response("-ERR User not set, try: USER <username>");
    return this.response("+OK User accepted");
}

// PASS - Performs basic authentication, runs after USER
POP3Server.prototype.cmdPASS = function(password){
    if(this.state!=this.N3.States.AUTHENTICATION) return this.response("-ERR Only allowed in authentication mode");
    if(!this.user) return this.response("-ERR USER not yet set");
    
    if(typeof this.authCallback=="function"){
        if(!this.authCallback(this.user, function(pass){
            return pass==password;
        })){
            delete this.user;
            return this.response("-ERR [AUTH] Invalid login");
        }
    }
    
    var response;
    if((response = this.afterLogin())===true){
        this.state = this.N3.States.TRANSACTION;
        return this.response("+OK You are now logged in");
    }else
        return this.response(response || "-ERR [SYS] Error with initializing");
}

// TRANSACTION commands

// NOOP - always responds with +OK
POP3Server.prototype.cmdNOOP = function(){
    if(this.state!=this.N3.States.TRANSACTION) return this.response("-ERR Only allowed in transaction mode");
    this.response("+OK");
}
    
POP3Server.prototype._cmdSTATResponse = function(err, length, size) {
    if(err) {
        this.response("-ERR STAT failed")
    } else {
        this.response("+OK "+length+" "+size);
    }
}
// STAT Lists the total count and bytesize of the messages
POP3Server.prototype.cmdSTAT = function(){
    if(this.state!=this.N3.States.TRANSACTION) return this.response("-ERR Only allowed in transaction mode");

    this.messages.stat(this._cmdSTATResponse.bind(this));
    
}

POP3Server.prototype._cmdLISTResponse = function(err, list){
    if(err){
        return this.response("-ERR LIST command failed")
    }
    if(!list)
        return this.response("-ERR Invalid message ID");
    
    if(typeof list == "string"){
        this.response("+OK "+list);
    }else{
        this.response("+OK");
        for(var i=0;i<list.length;i++){
            this.response(list[i]);
        }
        this.response(".");
    }
}

// LIST [msg] lists all messages
POP3Server.prototype.cmdLIST = function(msg){
    if(this.state!=this.N3.States.TRANSACTION) return this.response("-ERR Only allowed in transaction mode");
    
    this.messages.list(msg, this._cmdLISTResponse.bind(this));
}

POP3Server.prototype._cmdUIDLResponse = function(err, list){
    if(err){
        return this.response("-ERR UIDL command failed")
    }

    if(!list)
        return this.response("-ERR Invalid message ID");
    
    if(typeof list == "string"){
        this.response("+OK "+list);
    }else{
        this.response("+OK");
        for(var i=0;i<list.length;i++){
            this.response(list[i]);
        }
        this.response(".");
    }
}
// UIDL - lists unique identifiers for stored messages
POP3Server.prototype.cmdUIDL = function(msg){
    if(this.state!=this.N3.States.TRANSACTION) return this.response("-ERR Only allowed in transaction mode");
    
    this.messages.uidl(msg, this._cmdUIDLResponse.bind(this));
}

POP3Server.prototype._cmdRETRResponse = function(err, message){
    if(err){
        return this.response("-ERR RETR command failed")
    }
    if(!message){
        return this.response("-ERR Invalid message ID");
    }
    this.response("+OK "+message.length+" octets");
    this.response(message);
    this.response(".");
}
// RETR msg - outputs a selected message
POP3Server.prototype.cmdRETR = function(msg){
    if(this.state!=this.N3.States.TRANSACTION) return this.response("-ERR Only allowed in transaction mode");
    
    this.messages.retr(msg, this._cmdRETRResponse.bind(this));

}

POP3Server.prototype._cmdDELEResponse = function(err, success){
    if(err){
        return this.response("-ERR RETR command failed")
    }
    if(!success){
        return this.response("-ERR Invalid message ID");
    }else{
        this.response("+OK msg deleted");
    }
}
// DELE msg - marks selected message for deletion
POP3Server.prototype.cmdDELE = function(msg){
    if(this.state!=this.N3.States.TRANSACTION) return this.response("-ERR Only allowed in transaction mode");
    
    this.messages.dele(msg, this._cmdDELEResponse.bind(this));

}

// RSET - resets DELE'ted message flags
POP3Server.prototype.cmdRSET = function(){
    if(this.state!=this.N3.States.TRANSACTION) return this.response("-ERR Only allowed in transaction mode");
    this.messages.rset();
    this.response("+OK");
}


// UTILITY FUNCTIONS

// Creates a MD5 hash
function md5(str){
    var hash = crypto.createHash('md5');
    hash.update(str);
    return hash.digest("hex").toLowerCase();
}

this.POP3Server = POP3Server;