event ldap::message(c: connection, is_orig: bool, messageID: count, opcode: ldap::ProtocolOpcode)
{
  print "LDAP message", c$id, is_orig, messageID, opcode;
}