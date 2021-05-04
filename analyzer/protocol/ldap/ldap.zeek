module ldap;

export {
  redef enum Log::ID += { LDAP_LOG };

  #############################################################################
  # This is the format of ldap.log
  # Each line represents a unique connection+message_id (requests/responses)
  type Info: record {

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

    # Result(s)
    result: set[ldap::ResultCode] &log &optional;

    # result matched DN(s)
    matchedDN: vector of string &log &optional;

    # result diagnostic message(s)
    diagnosticMessage: vector of string &log &optional;

    # object(s) (eg., search strings, some other arguments of whatever operations)
    object: vector of string &log &optional;

    # The analyzer ID used for the analyzer instance attached
    # to each connection.  It is not used for logging since it's a
    # meaningless arbitrary number.
    analyzer_id: count &optional;
  };

  # Event that can be handled to access the ldap record as it is sent on
  # to the logging framework.
  global log_ldap: event(rec: ldap::Info);

  # Event called for each LDAP message (either direction)
  global ldap::message: event(c: connection,
                              is_orig: bool,
                              message_id: int,
                              opcode: ldap::ProtocolOpcode,
                              result: ldap::ResultCode,
                              matchedDN: string,
                              diagnosticMessage: string,
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

#############################################################################
redef record connection += {
  ldap_messages: table[int] of Info &optional;
};

#############################################################################
event zeek_init() &priority=5 {
  Log::create_stream(ldap::LDAP_LOG, [$columns=Info, $ev=log_ldap, $path="ldap"]);
}

#############################################################################
function set_session(c: connection, message_id: int) {
  if (! c?$ldap_messages )
    c$ldap_messages = table();

  if ( message_id !in c$ldap_messages ) {
    local aid: count = 0;
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
    set_session(c, 0);
    c$ldap_messages[0]$analyzer_id = aid;
  }
}

#############################################################################
event ldap::message(c: connection,
                    is_orig: bool,
                    message_id: int,
                    opcode: ldap::ProtocolOpcode,
                    result: ldap::ResultCode,
                    matchedDN: string,
                    diagnosticMessage: string,
                    object: string) {

  set_session(c, message_id);

  if ( ! c$ldap_messages[message_id]?$opcode )
    c$ldap_messages[message_id]$opcode = set();
  add c$ldap_messages[message_id]$opcode[opcode];

  if ( result != ldap::ResultCode_NOT_SET ) {
    if ( ! c$ldap_messages[message_id]?$result )
      c$ldap_messages[message_id]$result = set();
    add c$ldap_messages[message_id]$result[result];
  }

  if ( matchedDN != "" ) {
    if ( ! c$ldap_messages[message_id]?$matchedDN )
      c$ldap_messages[message_id]$matchedDN = vector();
    c$ldap_messages[message_id]$matchedDN += matchedDN;
  }

  if ( diagnosticMessage != "" ) {
    if ( ! c$ldap_messages[message_id]?$diagnosticMessage )
      c$ldap_messages[message_id]$diagnosticMessage = vector();
    c$ldap_messages[message_id]$diagnosticMessage += diagnosticMessage;
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

#############################################################################
event connection_state_remove(c: connection) {
  if ( (! c?$ldap_messages ) || (|c$ldap_messages| == 0) )
    return;

  # log any "pending" unlogged LDAP messages
  for ( [mid], m in c$ldap_messages ) {
    if (mid > 0) {
      Log::write(ldap::LDAP_LOG, m);
    }
  }
  delete c$ldap_messages;
}