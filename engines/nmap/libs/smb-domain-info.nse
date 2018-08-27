local smb = require "smb"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Attempts to enumerate domains on a system, along with their policies. This generally requires
credentials, except against Windows 2000. In addition to the actual domain, the "Builtin"
domain is generally displayed. Windows returns this in the list of domains, but its policies
don't appear to be used anywhere.

Much of the information provided is useful to a penetration tester, because it tells the
tester what types of policies to expect. For example, if passwords have a minimum length of 8,
the tester can trim his database to match; if the minimum length is 14, the tester will
probably start looking for sticky notes on people's monitors.
]]

-- @usage
-- nmap --script smb-domain-info.nse -p445 <host>
--
-- @output
-- Host script results:
-- | smb-domain-info:
-- |   lanmanager: Windows Server 2012 R2 Standard 6.3
-- |   ip: 10.11.1.1
-- |   date: 2018-08-27T12:22:19
-- |   timezone_str: UTC+2.0
-- |   domain: INTRA
-- |   server: myserver
-- |   os: Windows Server 2012 R2 Standard 9600
-- |   forest_dns: dom.local
-- |   domain_dns: intra.dom.local
-- |_  fqdn: myserver.intra.dom.local
-----------------------------------------------------------------------

author = "Nicolas Mattiocco"
copyright = "Nicolas Mattiocco"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery"}

hostrule = function(host)
  return smb.get_port(host) ~= nil
end

action = function(host)
  -- Begin SMB Session
  local status, smbstate = smb.start(host)
  if(status == false) then
    return false, smbstate
  end

  -- Negotiate the protocol
  local status, err = smb.negotiate_protocol(smbstate, {})
  if(status == false) then
    smb.stop(smbstate)
    return false, err
  end

  -- Start up a session
  status, err = smb.start_session(smbstate, {})
  smb.stop(smbstate)

  local response = stdnse.output_table()
  local relevant_keys = { "lanmanager", "ip", "date", "timezone_str", "domain", "server", "os", "forest_dns", "domain_dns", "fqdn" }
  local i = 1
  while i <= #relevant_keys do
    -- stdnse.debug1("current key: %s", tostring(relevant_keys[i]))
    if (smbstate[relevant_keys[i]] ~= nil) then
      stdnse.debug1("current value: %s --> %s", tostring(relevant_keys[i]), tostring(smbstate[relevant_keys[i]]))
      response[relevant_keys[i]] = tostring(smbstate[relevant_keys[i]])
    end
    i=i+1
  end

  return response

end
