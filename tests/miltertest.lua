-- https://mopano.github.io/sendmail-filter-api/constant-values.html#com.sendmail.milter.MilterConstants
-- http://www.opendkim.org/miltertest.8.html

-- socket must be defined as miltertest global variable (-D)
conn = mt.connect(socket)
if conn == nil then
  error "mt.connect() failed"
end

mt.set_timeout(3)

-- 5321.FROM
if mt.mailfrom(conn, "envelope.sender@example.org") ~= nil then
  error "mt.mailfrom() failed"
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
  error "mt.mailfrom() unexpected reply"
end

-- 5321.RCPT+MACROS
mt.macro(conn, SMFIC_RCPT, '{client_addr}', "127.128.129.130", "i", "4CgSNs5Q9sz7SllQ", '{cert_subject}', "mail.protection.outlook.com")
if mt.rcptto(conn, "<envelope.recipient@example.com>") ~= nil then
  error "mt.rcptto() failed"
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
  error "mt.rcptto() unexpected reply"
end

-- HEADER
if mt.header(conn, "From", '"Blah Blubb" <O365ConnectorValidation@lalalulu.onmicrosoft.com>') ~= nil then
  error "mt.header(From) failed"  
end
if mt.header(conn, "X-MS-Exchange-CrossTenant-Id", "1234abcd-18c5-45e8-88de-123456789abc") ~= nil then
  error "mt.header(Subject) failed"  
end
--if mt.header(conn, "X-MS-Exchange-CrossTenant-Id", "4321abcd-18c5-45e8-88de-blahblubb") ~= nil then
--  error "mt.header(Subject) failed"  
--end
if mt.header(conn, "Authentication-Results", "another-wrong-auth-serv-id;\n  dkim=fail header.d=lalalulu.onmicrosoft.com header.s=selector1-lalalulu-onmicrosoft-com header.b=mmmjFpv8") ~= nil then
  error "mt.header(Subject) failed"  
end
if mt.header(conn, "Authentication-Results", "wrong-auth-serv-id;\n  dkim=pass header.d=lalalulu.onmicrosoft.com header.s=selector1-lalalulu-onmicrosoft-com header.b=mmmjFpv8") ~= nil then
  error "mt.header(Subject) failed"  
end
if mt.header(conn, "Authentication-Results", "my-auth-serv-id;\n  dkim=pass header.d=lalalulu.onmicrosoft.com header.s=selector1-lalalulu-onmicrosoft-com header.b=mmmjFpv8") ~= nil then
  error "mt.header(Subject) failed"  
end
if mt.header(conn, "Authentication-Results", "my-auth-serv-id;\n  dkim=fail header.d=lalalulu.onmicrosoft.com header.s=selector2-asdf header.b=mmmjFpv8") ~= nil then
  error "mt.header(Subject) failed"  
end
if mt.header(conn, "Authentication-Results", "some-validating-host;\n dkim=pass header.d=paypal.de header.s=pp-dkim1 header.b=PmTtUzer;\n dmarc=pass (policy=reject) header.from=paypal.de;\n spf=pass (some-validating-host: domain of service@paypal.de designates 173.0.84.226 as permitted sender) smtp.mailfrom=service@paypal.de") ~= nil then
  error "mt.header(Subject) failed"  
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

if not mt.eom_check(conn, MT_HDRADD, "X-SOS-Milter") then
  mt.echo("no header added")
else
  mt.echo("X-SOS-Milter header added -> LDAP-Domain with broken SPF")
end

-- DISCONNECT
mt.disconnect(conn)