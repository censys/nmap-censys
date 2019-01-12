local http = require "http"
local base64 = require "base64"
local io = require "io"
local ipOps = require "ipOps"
local json = require "json"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local tab = require "tab"
local table = require "table"
local openssl = stdnse.silent_require "openssl"

-- Set your Censys API key here to avoid typing it in every time:
local apiId = ""
local apiSecret = ""

author = "Jose Nazario <jose@censys.io>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "external"}

description = [[
Queries Censys API for given targets and produces similar output to
a -sV nmap scan. The Censys API ID and secret can be set with the 'apiid' and 
'apisecret' script arguments, CENSYS_API_ID and CENSYS_API_SECRET environment 
variables, or hardcoded in the .nse file itself. You can get free API 
credentials from https://censys.io/api

N.B if you want this script to run completely passively make sure to
include the -sn -Pn -n flags.
]]

---
-- @usage
--  nmap --script censys-api x.y.z.0/24 -sn -Pn -n --script-args 'censys-api.outfile=potato.csv,censys-api.apiid=CENSYS_API_ID,censys-api.apisecret=CENSYS_API_SECRET'
--  nmap --script censys-api --script-args 'censys-api.target=x.y.z.a,censys-api.apiid=CENSYS_API_ID,censys-api.apisecret=CENSYS_API_SECRET'
--
-- @output
-- | censys-api: Report for 45.33.32.156 ()
-- | PORT  PROTO  PRODUCT  VERSION
-- | 80    http   httpd    2.4.7
-- |_22    ssh    OpenSSH  6.6.1p1
--
--@args censys-api.outfile Write the results to the specified CSV file
--@args censys-api.apiid Specify the Censys API ID. This can also be hardcoded in the nse file.
--@args censys-api.apisecret Specify the Censys API secret. This can also be hardcoded in the nse file.
--@args censys-api.target Specify a single target to be scanned.
--
--@xmloutput
-- <table key="hostnames">
--   <elem>scanme.nmap.org</elem>
-- </table>
-- <table key="ports">
--   <table>
--     <elem key="protocol">tcp</elem>
--     <elem key="number">22</elem>
--   </table>
--   <table>
--     <elem key="version">2.4.7</elem>
--     <elem key="product">Apache httpd</elem>
--     <elem key="protocol">tcp</elem>
--     <elem key="number">80</elem>
--   </table>
-- </table>

-- ToDo: * Have an option to complement non-banner scans with Censys data (e.g. -sS scan, but
--          grab service info from Censys
--       * Have script arg to include extra host info. e.g. Coutry/city of IP, datetime of
--          scan, verbose port output (e.g. smb share info)
--       * Warn user if they haven't set -sn -Pn and -n (and will therefore actually scan the host
--       * Accept IP ranges via the script argument 'target' parameter


-- Begin
if not nmap.registry[SCRIPT_NAME] then
  nmap.registry[SCRIPT_NAME] = {
    apiId = stdnse.get_script_args(SCRIPT_NAME .. ".apiid") or os.getenv("CENSYS_API_ID") or apiId,
	apiSecret = stdnse.get_script_args(SCRIPT_NAME .. ".apisecret") or os.getenv("CENSYS_API_SECRET") or apiSecret,
    count = 0
  }
end

local registry = nmap.registry[SCRIPT_NAME]
local outFile = stdnse.get_script_args(SCRIPT_NAME .. ".outfile")
local arg_target = stdnse.get_script_args(SCRIPT_NAME .. ".target")

local function lookup_target(target)	
  local option={header={}}
  option['header']["Authorization"]= "Basic " .. base64.enc(registry.apiId .. ":" .. registry.apiSecret) 
  local response = http.get("www.censys.io", 443, "/api/v1/view/ipv4/" .. target, option)
  if response.status == 404 then
    stdnse.debug1("Host not found: %s", target)
    return nil
  elseif (response.status ~= 200) then
    stdnse.debug1("Bad response from Censys for IP %s : %s", target, response.status)
    return nil
  end

  local stat, resp = json.parse(response.body)
  if not stat then
    stdnse.debug1("Error parsing Censys response: %s", resp)
    return nil
  end

  return resp
end

local function format_output(resp)
    if resp.error then
      return resp.error
    end
	
    if resp.protocols then
		registry.count = registry.count + 1		
	    local out = { hostnames = {}, ports = {} }
	    local ports = out.ports
	    local tab_out = tab.new()
	    tab.addrow(tab_out, "PORT", "PROTO", "PRODUCT", "VERSION")

	    for n, port in pairs(resp.protocols) do
  			  portnum, proto = string.match(port, "([0-9]+)/(.*)")		
			  local _, subproto = next(resp[portnum][proto])  
	  	      ports[n] = {
	  	        number = portnum,
	  	        protocol = proto,
	  	        product = (subproto["metadata"] or {})["product"] or "",
	  	        version = (subproto["metadata"] or {})["version"] or "",
	  	      }
	  	      tab.addrow(tab_out, portnum, proto, (subproto["metadata"] or {})["product"] or "", (subproto["metadata"] or {})["version"] or "")
	    end
	    return out, tab.dump(tab_out)		
	else
	    return "Unable to query data"
    end
end

prerule = function ()
  if (outFile ~= nil) then
    local file = io.open(outFile, "w")
    io.output(file)
    io.write("IP,Port,Proto,Product,Version\n")
  end
  
  if registry.apiId == "" then
    registry.apiId = nil
  end

  if registry.apiSecret == "" then
    registry.apiSecret = nil
  end

  if not registry.apiId or not registry.apiSecret then
    stdnse.verbose1("Error: Please specify your Censys API ID and secret with the %s.apiid and %s.apisecret arguments", SCRIPT_NAME, SCRIPT_NAME)
    return false
  end

  local option={header={}}
  option['header']["Authorization"]= "Basic " .. base64.enc(registry.apiId .. ":" .. registry.apiSecret) 
  local response = http.get("www.censys.io", 443, "/api/v1/account", option)

  if (response.status ~= 200) then
    stdnse.verbose1("Error: Your Censys credentials (%s, %s) are invalid", registry.apiId, registry.apiSecret)
    -- Prevent further stages from running
    registry.apiId = nil
	registry.apiSecret = nil
    return false
  end

  if arg_target then
    local is_ip, err = ipOps.expand_ip(arg_target)
    if not is_ip then
      stdnse.verbose1("Error: %s.target must be an IP address", SCRIPT_NAME)
      return false
    end
    return true
  end
end

generic_action = function(ip)
  local resp = lookup_target(ip)
  if not resp then return nil end
  local out, tabular = format_output(resp)
  if type(out) == "string" then
    -- some kind of error
    return out
  end
  local result = string.format(
    "Report for %s (%s)\n%s",
    ip,
    table.concat(out.hostnames, ", "),
    tabular
    )
  if (outFile ~= nil) then
    for _, port in ipairs(out.ports) do
      io.write( string.format("%s,%s,%s,%s,%s\n",
          ip, port.number, port.protocol, port.product or "", port.version or "")
        )
    end
  end
  return out, result
end

preaction = function()
  return generic_action(arg_target)
end

hostrule = function(host)
  return registry.apiId and registry.apiSecret and not ipOps.isPrivate(host.ip)
end

hostaction = function(host)
  return generic_action(host.ip)
end

postrule = function ()
  return registry.apiId, registry.apiSecret
end

postaction = function ()
  local out = { "Censys done: ", registry.count, " hosts up." }
  if outFile then
    io.close()
    out[#out+1] = "\nWrote Censys output to: "
    out[#out+1] = outFile
  end
  return table.concat(out)
end

local ActionsTable = {
  -- prerule: scan target from script-args
  prerule = preaction,
  -- hostrule: look up a host in Censys
  hostrule = hostaction,
  -- postrule: report results
  postrule = postaction
}

-- execute the action function corresponding to the current rule
action = function(...) return ActionsTable[SCRIPT_TYPE](...) end
