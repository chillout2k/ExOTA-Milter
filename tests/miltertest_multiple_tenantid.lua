-- https://mopano.github.io/sendmail-filter-api/constant-values.html#com.sendmail.milter.MilterConstants
-- http://www.opendkim.org/miltertest.8.html

-- socket must be defined as miltertest global variable (-D)
conn = mt.connect(socket)
if conn == nil then
  error "mt.connect() failed"
end
if mt.conninfo(conn, "localhost", "::1") ~= nil then
  error "mt.conninfo() failed"
end

mt.set_timeout(60)

-- 5321.FROM
if mt.mailfrom(conn, "envelope.sender@example.org") ~= nil then
  error "mt.mailfrom() failed"
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
  error "mt.mailfrom() unexpected reply"
end

-- 5321.RCPT+MACROS
mt.macro(conn, SMFIC_RCPT, "i", "4CgSNs5Q9sz7SllQ", '{cert_subject}', "mail.protection.outlook.comx")
if mt.rcptto(conn, "<envelope.recipient@example.com>") ~= nil then
  error "mt.rcptto() failed"
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
  error "mt.rcptto() unexpected reply"
end

-- HEADER
if mt.header(conn, "fRoM", '"Blah Blubb" <O365ConnectorValidation@staging.zwackl.de>') ~= nil then
  error "mt.header(From) failed"  
end
if mt.header(conn, "x-mS-EXCHANGE-crosstenant-id", "1234abcd-18c5-45e8-88de-123456789abc") ~= nil then
  error "mt.header(tenant-id pass) failed"  
end
if mt.header(conn, "x-mS-EXCHANGE-crosstenant-id", "1234abcd-18c5-45e8-88de-123456789abc") ~= nil then
  error "mt.header(tenant-id pass) failed"  
end
if mt.header(conn, "X-MS-Exchange-CrossTenant-Id", "4321abcd-18c5-45e8-88de-blahblubb") ~= nil then
  error "mt.header(tenant-id fail) failed"  
end
if mt.header(conn, "Authentication-RESULTS", "my-auth-serv-id;\n  dkim=pass header.d=staging.zwackl.de header.s=selector1-yad-onmicrosoft-com header.b=mmmjFpv8") ~= nil then
  error "mt.header(DKIM-AR) failed"  
end
if mt.header(conn, "X-ExOTA-Authentication-Results", "my-auth-serv-id;\n exota=pass") ~= nil then
  error "mt.header(Exota-AR) failed"  
end

-- EOM
if mt.eom(conn) ~= nil then
  error "mt.eom() failed"
end
mt.echo("EOM: " .. mt.getreply(conn))
if mt.getreply(conn) == SMFIR_CONTINUE then
  mt.echo("EOM-continue")
elseif mt.getreply(conn) == SMFIR_REPLYCODE then
  mt.echo("EOM-reject")
end

if not mt.eom_check(conn, MT_HDRADD, "X-ExOTA-Authentication-Results") then
  mt.echo("no header added")
else
  mt.echo("X-ExOTA-Authentication-Results header added")
end

-- DISCONNECT
mt.disconnect(conn)