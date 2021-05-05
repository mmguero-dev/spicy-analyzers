module ldap;

export {
  redef enum Log::ID += { LDAP_LOG,
                          LDAP_SEARCH_LOG };

  #############################################################################
  # This is the format of ldap.log
  # Each line represents a unique connection+message_id (requests/responses)
  type Message: record {

    # Timestamp for when the event happened.
    ts: time &log;

    # Unique ID for the connection.
    uid: string &log;

    # The connection's 4-tuple of endpoint addresses/ports.
    id: conn_id &log;

    # Message ID
    message_id: int &log &optional;

    # Operation(s)
    opcode: set[ldap::ProtocolOpcode] &log &optional;

    # Result code(s)
    result: set[ldap::ResultCode] &log &optional;

    # result diagnostic message(s)
    diagnostic_message: vector of string &log &optional;

    # object(s) (eg., search strings, some other arguments of whatever operations)
    object: vector of string &log &optional;

    # The analyzer ID used for the analyzer instance attached
    # to each connection.  It is not used for logging since it's a
    # meaningless arbitrary number.
    analyzer_id: count &optional;
  };

  #############################################################################
  # This is the format of ldap.log
  # Each line represents a unique connection+message_id (requests/responses)
  type Search: record {

    # Timestamp for when the event happened.
    ts: time &log;

    # Unique ID for the connection.
    uid: string &log;

    # The connection's 4-tuple of endpoint addresses/ports.
    id: conn_id &log;

    # Message ID
    message_id: int &log &optional;

    # sets of search scope and deref alias
    scope: set[ldap::SearchScope] &log &optional;
    deref: set[ldap::SearchDerefAlias] &log &optional;

    # base search objects
    base_object: vector of string &log &optional;

    # number of results returned
    result_count: count &log &optional;

    # Result code (s)
    result: set[ldap::ResultCode] &log &optional;

    # result diagnostic message(s)
    diagnostic_message: vector of string &log &optional;

    # The analyzer ID used for the analyzer instance attached
    # to each connection.  It is not used for logging since it's a
    # meaningless arbitrary number.
    analyzer_id: count &optional;
  };

  # Event that can be handled to access the ldap record as it is sent on
  # to the logging framework.
  global log_ldap: event(rec: ldap::Message);
  global log_ldap_search: event(rec: ldap::Search);

  # Event called for each LDAP message (either direction)
  global ldap::message: event(c: connection,
                              message_id: int,
                              opcode: ldap::ProtocolOpcode,
                              result: ldap::ResultCode,
                              matched_dn: string,
                              diagnostic_message: string,
                              object: string);

}

#############################################################################
global OPCODES_FINISHED: set[ldap::ProtocolOpcode] = { ldap::ProtocolOpcode_BIND_RESPONSE,
                                                       ldap::ProtocolOpcode_UNBIND_REQUEST,
                                                       ldap::ProtocolOpcode_SEARCH_RESULT_DONE,
                                                       ldap::ProtocolOpcode_MODIFY_RESPONSE,
                                                       ldap::ProtocolOpcode_ADD_RESPONSE,
                                                       ldap::ProtocolOpcode_DEL_RESPONSE,
                                                       ldap::ProtocolOpcode_MOD_DN_RESPONSE,
                                                       ldap::ProtocolOpcode_COMPARE_RESPONSE,
                                                       ldap::ProtocolOpcode_ABANDON_REQUEST,
                                                       ldap::ProtocolOpcode_EXTENDED_RESPONSE };

global OPCODES_SEARCH: set[ldap::ProtocolOpcode] = { ldap::ProtocolOpcode_SEARCH_REQUEST,
                                                     ldap::ProtocolOpcode_SEARCH_RESULT_ENTRY,
                                                     ldap::ProtocolOpcode_SEARCH_RESULT_DONE,
                                                     ldap::ProtocolOpcode_SEARCH_RESULT_REFERENCE };

#############################################################################
redef record connection += {
  ldap_messages: table[int] of Message &optional;
  ldap_searches: table[int] of Search &optional;
};

#############################################################################
event zeek_init() &priority=5 {
  Log::create_stream(ldap::LDAP_LOG, [$columns=Message, $ev=log_ldap, $path="ldap"]);
  Log::create_stream(ldap::LDAP_SEARCH_LOG, [$columns=Search, $ev=log_ldap_search, $path="ldap_search"]);
}

#############################################################################
function set_session(c: connection, message_id: int, opcode: ldap::ProtocolOpcode) {

  if (! c?$ldap_messages )
    c$ldap_messages = table();

  if (! c?$ldap_searches )
    c$ldap_searches = table();

  local aid: count = 0;
  if ((opcode in OPCODES_SEARCH) && (message_id !in c$ldap_searches)) {
    if ( 0 in c$ldap_messages ) {
      aid = c$ldap_messages[0]$analyzer_id;
    }
    c$ldap_searches[message_id] = [$ts=network_time(),
                                   $uid=c$uid,
                                   $id=c$id,
                                   $message_id=message_id,
                                   $result_count=0,
                                   $analyzer_id=aid];

  } else if ((opcode !in OPCODES_SEARCH) && (message_id !in c$ldap_searches)) {
    if ( 0 in c$ldap_messages ) {
      aid = c$ldap_messages[0]$analyzer_id;
    }
    c$ldap_messages[message_id] = [$ts=network_time(),
                                   $uid=c$uid,
                                   $id=c$id,
                                   $message_id=message_id,
                                   $analyzer_id=aid];
  }

}

#############################################################################
event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count) &priority=5 {

  # todo: UDP hasn't been implemented/tested yet
  # atype == Analyzer::ANALYZER_SPICY_LDAP_UDP

  if ( atype == Analyzer::ANALYZER_SPICY_LDAP_TCP ) {
    set_session(c, 0, ldap::ProtocolOpcode_NOT_SET);
    c$ldap_messages[0]$analyzer_id = aid;
  }
}

#############################################################################
event ldap::message(c: connection,
                    message_id: int,
                    opcode: ldap::ProtocolOpcode,
                    result: ldap::ResultCode,
                    matched_dn: string,
                    diagnostic_message: string,
                    object: string) {

  if (opcode == ldap::ProtocolOpcode_SEARCH_RESULT_DONE) {
    set_session(c, message_id, opcode);

    if ( result != ldap::ResultCode_NOT_SET ) {
      if ( ! c$ldap_searches[message_id]?$result )
        c$ldap_searches[message_id]$result = set();
      add c$ldap_searches[message_id]$result[result];
    }

    if ( diagnostic_message != "" ) {
      if ( ! c$ldap_searches[message_id]?$diagnostic_message )
        c$ldap_searches[message_id]$diagnostic_message = vector();
      c$ldap_searches[message_id]$diagnostic_message += diagnostic_message;
    }

    Log::write(ldap::LDAP_SEARCH_LOG, c$ldap_searches[message_id]);
    delete c$ldap_searches[message_id];

  } else if (opcode !in OPCODES_SEARCH) {
    set_session(c, message_id, opcode);

    if ( ! c$ldap_messages[message_id]?$opcode )
      c$ldap_messages[message_id]$opcode = set();
    add c$ldap_messages[message_id]$opcode[opcode];

    if ( result != ldap::ResultCode_NOT_SET ) {
      if ( ! c$ldap_messages[message_id]?$result )
        c$ldap_messages[message_id]$result = set();
      add c$ldap_messages[message_id]$result[result];
    }

    if ( diagnostic_message != "" ) {
      if ( ! c$ldap_messages[message_id]?$diagnostic_message )
        c$ldap_messages[message_id]$diagnostic_message = vector();
      c$ldap_messages[message_id]$diagnostic_message += diagnostic_message;
    }

    if ( object != "" ) {
      if ( ! c$ldap_messages[message_id]?$object )
        c$ldap_messages[message_id]$object = vector();
      c$ldap_messages[message_id]$object += object;
    }

    if (opcode in OPCODES_FINISHED) {
      Log::write(ldap::LDAP_LOG, c$ldap_messages[message_id]);
      delete c$ldap_messages[message_id];
    }
  }

}

#############################################################################
event ldap::searchreq(c: connection,
                      message_id: int,
                      base_object: string,
                      scope: ldap::SearchScope,
                      deref: ldap::SearchDerefAlias,
                      size_limit: int,
                      time_limit: int,
                      types_only: bool) {

  set_session(c, message_id, ldap::ProtocolOpcode_SEARCH_REQUEST);

  if ( scope != ldap::SearchScope_SEARCH_NOT_SET ) {
    if ( ! c$ldap_searches[message_id]?$scope )
      c$ldap_searches[message_id]$scope = set();
    add c$ldap_searches[message_id]$scope[scope];
  }

  if ( deref != ldap::SearchDerefAlias_DEREF_NOT_SET ) {
    if ( ! c$ldap_searches[message_id]?$deref )
      c$ldap_searches[message_id]$deref = set();
    add c$ldap_searches[message_id]$deref[deref];
  }

  if ( base_object != "" ) {
    if ( ! c$ldap_searches[message_id]?$base_object )
      c$ldap_searches[message_id]$base_object = vector();
    c$ldap_searches[message_id]$base_object += base_object;
  }

}

#############################################################################
event connection_state_remove(c: connection) {

  # log any "pending" unlogged LDAP messages/searches

  if ( c?$ldap_messages && (|c$ldap_messages| > 0) ) {
    for ( [mid], m in c$ldap_messages ) {
      if (mid > 0) {
        Log::write(ldap::LDAP_LOG, m);
      }
    }
    delete c$ldap_messages;
  }

  if ( c?$ldap_searches && (|c$ldap_searches| > 0) ) {
    for ( [mid], s in c$ldap_searches ) {
      if (mid > 0) {
        Log::write(ldap::LDAP_SEARCH_LOG, s);
      }
    }
    delete c$ldap_searches;
  }

}