local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Returns authentication methods a winrm server supports.
]]

---
-- @usage
-- nmap --script winrm-auth-methods -p 5985 <target>
--
-- @output
-- 5985/tcp open  wsman
-- | winrm-auth-methods: 
-- |   Accepted Authentication Methods: 
-- |     Negotiate
-- |     Basic
-- |     Kerberos
-- |_    CredSSP

author = "Evangelos Deirmentzoglou"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

portrule = shortport.port_or_service({5985, 5986},{'wsman','wsmans'})

function generate_random_string(len, charset)
  local t = {}
  local ascii_A = 65
  local ascii_Z = 90
  if charset then
    for i=1,len do
      t[i]=charset[math.random(#charset)]
    end
  else
    for i=1,len do
      t[i]=string.char(math.random(ascii_A,ascii_Z))
    end
  end
  return table.concat(t)
end

action = function(host, port)

  local r = {}
  local result = stdnse.output_table()
  local randoms = generate_random_string(5)
  local url = "/wsman"
  local response = http.post( host, port, url, nil, nil, randoms )

  if response.header["www-authenticate"] and string.match(response.header["www-authenticate"], "Negotiate") then
    table.insert(r, "Negotiate")
  end
  if response.header["www-authenticate"] and string.match(response.header["www-authenticate"], "Basic") then
    table.insert(r, "Basic")
  end  
  if response.header["www-authenticate"] and string.match(response.header["www-authenticate"], "Kerberos") then
    table.insert(r, "Kerberos")
  end  
  if response.header["www-authenticate"] and string.match(response.header["www-authenticate"], "CredSSP") then
    table.insert(r, "CredSSP")
  end
  if #r > 0 then
    result = r
  else
    result = "Server does not support authentication."
  end

  return result
end
