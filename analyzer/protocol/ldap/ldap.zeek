module ldap;

export {
  redef enum Log::ID += { LDAP_LOG };

  # This is the format of ldap.log
  type Info: record {
    # Timestamp for when the event happened.
    ts: time &log;
    # Unique ID for the connection.
    uid: string &log;
    # The connection's 4-tuple of endpoint addresses/ports.
    id: conn_id &log;
    # Is orig
    is_orig: bool &log &optional;
    # Message ID
    message_id: count &log &optional;
    # Operation
    opcode: ldap::ProtocolOpcode &log &optional;

    # The analyzer ID used for the analyzer instance attached
    # to each connection.  It is not used for logging since it's a
    # meaningless arbitrary number.
    analyzer_id: count &optional;
  };

  # Event that can be handled to access the ldap record as it is sent on
  # to the logging framework.
  global log_ldap: event(rec: ldap::Info);

  global ldap::message: event(c: connection, is_orig: bool, message_id: count, opcode: ldap::ProtocolOpcode);

}

redef record connection += {
  ldap: Info &optional;
};

event zeek_init() &priority=5 {
  Log::create_stream(ldap::LDAP_LOG, [$columns=Info, $ev=log_ldap, $path="ldap"]);
}

function set_session(c: connection) {
  if ( ! c?$ldap ) {
    c$ldap = [$ts=network_time(), $uid=c$uid, $id=c$id];
  }
}

event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count) &priority=5 {
  if ( atype == Analyzer::ANALYZER_SPICY_LDAP_TCP ||
       atype == Analyzer::ANALYZER_SPICY_LDAP_UDP ) {
    set_session(c);
    c$ldap$analyzer_id = aid;
  }
}

event ldap::message(c: connection, is_orig: bool, message_id: count, opcode: ldap::ProtocolOpcode) {
  set_session(c);
  c$ldap$is_orig = is_orig;
  c$ldap$message_id = message_id;
  c$ldap$opcode = opcode;

  Log::write(ldap::LDAP_LOG, c$ldap);
  delete c$ldap;
}
