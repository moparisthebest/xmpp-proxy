-- mod_net_proxy.lua
-- Copyright (C) 2018 Pascal Mathis <mail@pascalmathis.com>
--
-- Implementation of PROXY protocol versions 1 and 2
-- Specifications: https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt

module:set_global();

-- Imports
local softreq = require "util.dependencies".softreq;
local bit = assert(softreq "bit" or softreq "bit32" or softreq "util.bitcompat", "No bit module found. See https://prosody.im/doc/depends#bitop");
local hex = require "util.hex";
local ip = require "util.ip";
local net = require "util.net";
local set = require "util.set";
local portmanager = require "core.portmanager";

-- Backwards Compatibility
local function net_ntop_bc(input)
	if input:len() == 4 then
		return string.format("%d.%d.%d.%d", input:byte(1, 4));
	elseif input:len() == 16 then
		local octets = { nil, nil, nil, nil, nil, nil, nil, nil };

		-- Convert received bytes into IPv6 address and skip leading zeroes for each group
		for index = 1, 8 do
			local high, low = input:byte(index * 2 - 1, index * 2);
			octets[index] = string.format("%x", high * 256 + low);
		end
		local address = table.concat(octets, ":", 1, 8);

		-- Search for the longest sequence of zeroes
		local token;
		local length = (address:match("^0:[0:]+()") or 1) - 1;
		for s in address:gmatch(":0:[0:]+") do
			if length < #s then
				length, token = #s, s;
			end
		end

		-- Return the shortened IPv6 address
		return address:gsub(token or "^0:[0:]+", "::", 1);
	end
end

local net_ntop = net.ntop or net_ntop_bc

-- Utility Functions
local function _table_invert(input)
	local output = {};
	for key, value in pairs(input) do
		output[value] = key;
	end
	return output;
end

-- Constants
local ADDR_FAMILY = { UNSPEC = 0x0, INET = 0x1, INET6 = 0x2, UNIX = 0x3 };
local ADDR_FAMILY_STR = _table_invert(ADDR_FAMILY);
local TRANSPORT = { UNSPEC = 0x0, STREAM = 0x1, DGRAM = 0x2 };
local TRANSPORT_STR = _table_invert(TRANSPORT);

local PROTO_MAX_HEADER_LENGTH = 256;
local PROTO_HANDLERS = {
	PROXYv1 = { signature = hex.from("50524F5859"), callback = nil },
	PROXYv2 = { signature = hex.from("0D0A0D0A000D0A515549540A"), callback = nil }
};
local PROTO_HANDLER_STATUS = { SUCCESS = 0, POSTPONE = 1, FAILURE = 2 };

-- Configuration Variables
local config_mappings = module:get_option("proxy_port_mappings", {});
local config_ports = module:get_option_set("proxy_ports", {});
local config_trusted_proxies = module:get_option_set("proxy_trusted_proxies", {"127.0.0.1", "::1"});

-- Persistent In-Memory Storage
local sessions = {};
local mappings = {};
local trusted_networks = set.new();

-- Proxy Data Methods
local proxy_data_mt = {}; proxy_data_mt.__index = proxy_data_mt;

function proxy_data_mt:describe()
	return string.format("proto=%s/%s src=%s:%d dst=%s:%d",
		self:addr_family_str(), self:transport_str(), self:src_addr(), self:src_port(), self:dst_addr(), self:dst_port());
end

function proxy_data_mt:addr_family_str()
	return ADDR_FAMILY_STR[self._addr_family] or ADDR_FAMILY_STR[ADDR_FAMILY.UNSPEC];
end

function proxy_data_mt:transport_str()
	return TRANSPORT_STR[self._transport] or TRANSPORT_STR[TRANSPORT.UNSPEC];
end

function proxy_data_mt:version()
	return self._version;
end

function proxy_data_mt:addr_family()
	return self._addr_family;
end

function proxy_data_mt:transport()
	return self._transport;
end

function proxy_data_mt:src_addr()
	return self._src_addr;
end

function proxy_data_mt:src_port()
	return self._src_port;
end

function proxy_data_mt:dst_addr()
	return self._dst_addr;
end

function proxy_data_mt:dst_port()
	return self._dst_port;
end

-- Protocol Handler Functions
PROTO_HANDLERS["PROXYv1"].callback = function(conn, session)
	local addr_family_mappings = { TCP4 = ADDR_FAMILY.INET, TCP6 = ADDR_FAMILY.INET6 };

	-- Postpone processing if CRLF (PROXYv1 header terminator) does not exist within buffer
	if session.buffer:find("\r\n") == nil then
		return PROTO_HANDLER_STATUS.POSTPONE, nil;
	end

	-- Declare header pattern and match current buffer against pattern
	local header_pattern = "^PROXY (%S+) (%S+) (%S+) (%d+) (%d+)\r\n";
	local addr_family, src_addr, dst_addr, src_port, dst_port = session.buffer:match(header_pattern);
	src_port, dst_port = tonumber(src_port), tonumber(dst_port);

	-- Ensure that header was successfully parsed and contains a valid address family
	if addr_family == nil or src_addr == nil or dst_addr == nil or src_port == nil or dst_port == nil then
		module:log("warn", "Received unparseable PROXYv1 header from %s", conn:ip());
		return PROTO_HANDLER_STATUS.FAILURE, nil;
	end
	if addr_family_mappings[addr_family] == nil then
		module:log("warn", "Received invalid PROXYv1 address family from %s: %s", conn:ip(), addr_family);
		return PROTO_HANDLER_STATUS.FAILURE, nil;
	end

	-- Ensure that received source and destination ports are within 1 and 65535 (0xFFFF)
	if src_port <= 0 or src_port >= 0xFFFF then
		module:log("warn", "Received invalid PROXYv1 source port from %s: %d", conn:ip(), src_port);
		return PROTO_HANDLER_STATUS.FAILURE, nil;
	end
	if dst_port <= 0 or dst_port >= 0xFFFF then
		module:log("warn", "Received invalid PROXYv1 destination port from %s: %d", conn:ip(), dst_port);
		return PROTO_HANDLER_STATUS.FAILURE, nil;
	end

	-- Ensure that received source and destination address can be parsed
	local _, err = ip.new_ip(src_addr);
	if err ~= nil then
		module:log("warn", "Received unparseable PROXYv1 source address from %s: %s", conn:ip(), src_addr);
		return PROTO_HANDLER_STATUS.FAILURE, nil;
	end
	_, err = ip.new_ip(dst_addr);
	if err ~= nil then
		module:log("warn", "Received unparseable PROXYv1 destination address from %s: %s", conn:ip(), dst_addr);
		return PROTO_HANDLER_STATUS.FAILURE, nil;
	end

	-- Strip parsed header from session buffer and build proxy data
	session.buffer = session.buffer:gsub(header_pattern, "");

	local proxy_data = {
		_version = 1,
		_addr_family = addr_family, _transport = TRANSPORT.STREAM,
		_src_addr = src_addr, _src_port = src_port,
		_dst_addr = dst_addr, _dst_port = dst_port
	};
	setmetatable(proxy_data, proxy_data_mt);

	-- Return successful response with gathered proxy data
	return PROTO_HANDLER_STATUS.SUCCESS, proxy_data;
end

PROTO_HANDLERS["PROXYv2"].callback = function(conn, session)
	-- Postpone processing if less than 16 bytes are available
	if #session.buffer < 16 then
		return PROTO_HANDLER_STATUS.POSTPONE, nil;
	end

	-- Parse first 16 bytes of protocol header
	local version = bit.rshift(bit.band(session.buffer:byte(13), 0xF0), 4);
	local command = bit.band(session.buffer:byte(13), 0x0F);
	local addr_family = bit.rshift(bit.band(session.buffer:byte(14), 0xF0), 4);
	local transport = bit.band(session.buffer:byte(14), 0x0F);
	local length = bit.bor(session.buffer:byte(16), bit.lshift(session.buffer:byte(15), 8));

	-- Postpone processing if less than 16+<length> bytes are available
	if #session.buffer < 16 + length then
		return PROTO_HANDLER_STATUS.POSTPONE, nil;
	end

	-- Ensure that version number is correct
	if version ~= 0x2 then
		module:log("warn", "Received unsupported PROXYv2 version from %s: %d", conn:ip(), version);
		return PROTO_HANDLER_STATUS.FAILURE, nil;
	end

	local payload = session.buffer:sub(17);
	if command == 0x0 then
		-- Gather source/destination addresses and ports from local socket
		local src_addr, src_port = conn:socket():getpeername();
		local dst_addr, dst_port = conn:socket():getsockname();

		-- Build proxy data based on real connection information
		local proxy_data = {
			_version = version,
			_addr_family = addr_family, _transport = transport,
			_src_addr = src_addr, _src_port = src_port,
			_dst_addr = dst_addr, _dst_port = dst_port
		};
		setmetatable(proxy_data, proxy_data_mt);

		-- Return successful response with gathered proxy data
		return PROTO_HANDLER_STATUS.SUCCESS, proxy_data;
	elseif command == 0x1 then
		local offset = 1;
		local src_addr, src_port, dst_addr, dst_port;

		-- Verify transport protocol is either STREAM or DGRAM
		if transport ~= TRANSPORT.STREAM and transport ~= TRANSPORT.DGRAM then
			module:log("warn", "Received unsupported PROXYv2 transport from %s: 0x%02X", conn:ip(), transport);
			return PROTO_HANDLER_STATUS.FAILURE, nil;
		end

		-- Parse source and destination addresses
		if addr_family == ADDR_FAMILY.INET then
			src_addr = net_ntop(payload:sub(offset, offset + 3)); offset = offset + 4;
			dst_addr = net_ntop(payload:sub(offset, offset + 3)); offset = offset + 4;
		elseif addr_family == ADDR_FAMILY.INET6 then
			src_addr = net_ntop(payload:sub(offset, offset + 15)); offset = offset + 16;
			dst_addr = net_ntop(payload:sub(offset, offset + 15)); offset = offset + 16;
		elseif addr_family == ADDR_FAMILY.UNIX then
			src_addr = payload:sub(offset, offset + 107); offset = offset + 108;
			dst_addr = payload:sub(offset, offset + 107); offset = offset + 108;
		end

		-- Parse source and destination ports
		if addr_family == ADDR_FAMILY.INET or addr_family == ADDR_FAMILY.INET6 then
			src_port = bit.bor(payload:byte(offset + 1), bit.lshift(payload:byte(offset), 8)); offset = offset + 2;
			-- luacheck: ignore 311
			dst_port = bit.bor(payload:byte(offset + 1), bit.lshift(payload:byte(offset), 8)); offset = offset + 2;
		end

		-- Strip parsed header from session buffer and build proxy data
		session.buffer = session.buffer:sub(17 + length);

		local proxy_data = {
			_version = version,
			_addr_family = addr_family, _transport = transport,
			_src_addr = src_addr, _src_port = src_port,
			_dst_addr = dst_addr, _dst_port = dst_port
		};
		setmetatable(proxy_data, proxy_data_mt);

		-- Return successful response with gathered proxy data
		return PROTO_HANDLER_STATUS.SUCCESS, proxy_data;
	else
		module:log("warn", "Received unsupported PROXYv2 command from %s: 0x%02X", conn:ip(), command);
		return PROTO_HANDLER_STATUS.FAILURE, nil;
	end
end

-- Wrap an existing connection with the provided proxy data. This will override several methods of the 'conn' object to
-- return the proxied source instead of the source which initiated the TCP connection. Afterwards, the listener of the
-- connection gets set according to the globally defined port<>service mappings and the methods 'onconnect' and
-- 'onincoming' are being called manually with the current session buffer.
local function wrap_proxy_connection(conn, session, proxy_data)
	-- Override and add functions of 'conn' object when source information has been collected
	conn.proxyip, conn.proxyport = conn.ip, conn.port;
	if proxy_data:src_addr() ~= nil and proxy_data:src_port() ~= nil then
		conn.ip = function()
			return proxy_data:src_addr();
		end
		conn.port = function()
			return proxy_data:src_port();
		end
		conn.clientport = conn.port;
	end

	-- Attempt to find service by processing port<>service mappings
	local mapping = mappings[tonumber(conn:serverport())];
	if mapping == nil then
		conn:close();
		module:log("warn", "Connection %s@%s terminated: Could not find mapping for port %d",
			conn:ip(), conn:proxyip(), conn:serverport());
		return;
	end

	if mapping.service == nil then
		local service = portmanager.get_service(mapping.service_name);

		if service ~= nil then
			mapping.service = service;
		else
			conn:close();
			module:log("warn", "Connection %s@%s terminated: Could not process mapping for unknown service %s",
				conn:ip(), conn:proxyip(), mapping.service_name);
			return;
		end
	end

	-- Pass connection to actual service listener and simulate onconnect/onincoming callbacks
	local service_listener = mapping.service.listener;

	module:log("info", "Passing proxied connection %s:%d to service %s", conn:ip(), conn:port(), mapping.service_name);
	conn:setlistener(service_listener);
	if service_listener.onconnect then
		service_listener.onconnect(conn);
	end
	return service_listener.onincoming(conn, session.buffer);
end

local function is_trusted_proxy(conn)
	-- If no trusted proxies were configured, trust any incoming connection
	-- While this may seem insecure, the module defaults to only trusting 127.0.0.1 and ::1
	if trusted_networks:empty() then
		return true;
	end

	-- Iterate through all trusted proxies and check for match against connected IP address
	local conn_ip = ip.new_ip(conn:ip());
	for trusted_network in trusted_networks:items() do
		if ip.match(trusted_network.ip, conn_ip, trusted_network.cidr) then
			return true;
		end
	end

	-- Connection does not match any trusted proxy
	return false;
end

-- Network Listener Methods
local listener = {};

function listener.onconnect(conn)
	-- Silently drop connections with an IP address of <nil>, which can happen when the socket was closed before the
	-- responsible net.server backend was able to grab the IP address of the connecting client.
	if conn:ip() == nil then
		conn:close();
		return;
	end

	-- Check if connection is coming from a trusted proxy
	if not is_trusted_proxy(conn) then
		conn:close();
		module:log("warn", "Dropped connection from untrusted proxy: %s", conn:ip());
		return;
	end

	-- Initialize session variables
	sessions[conn] = {
		handler = nil;
		buffer = nil;
	};
end

function listener.onincoming(conn, data)
	-- Abort processing if no data has been received
	if not data then
		return;
	end

	-- Lookup session for connection and append received data to buffer
	local session = sessions[conn];
	session.buffer = session.buffer and session.buffer .. data or data;

	-- Attempt to determine protocol handler if not done previously
	if session.handler == nil then
		-- Match current session buffer against all known protocol signatures to determine protocol handler
		for handler_name, handler in pairs(PROTO_HANDLERS) do
			if session.buffer:find("^" .. handler.signature) ~= nil then
				session.handler = handler.callback;
				module:log("debug", "Detected %s connection from %s:%d", handler_name, conn:ip(), conn:port());
				break;
			end
		end

		-- Decide between waiting for a complete header signature or terminating the connection when no handler has been found
		if session.handler == nil then
			-- Terminate connection if buffer size has exceeded tolerable maximum size
			if #session.buffer > PROTO_MAX_HEADER_LENGTH then
				conn:close();
				module:log("warn", "Connection %s:%d terminated: No valid PROXY header within %d bytes",
					conn:ip(), conn:port(), PROTO_MAX_HEADER_LENGTH);
			end

			-- Skip further processing without a valid protocol handler
			module:log("debug", "No valid header signature detected from %s:%d, waiting for more data...",
				conn:ip(), conn:port());
			return;
		end
	end

	-- Execute proxy protocol handler and process response
	local response, proxy_data = session.handler(conn, session);
	if response == PROTO_HANDLER_STATUS.SUCCESS then
		module:log("info", "Received PROXY header from %s: %s", conn:ip(), proxy_data:describe());
		return wrap_proxy_connection(conn, session, proxy_data);
	elseif response == PROTO_HANDLER_STATUS.POSTPONE then
		module:log("debug", "Postponed parsing of incomplete PROXY header received from %s", conn:ip());
		return;
	elseif response == PROTO_HANDLER_STATUS.FAILURE then
		conn:close();
		module:log("warn", "Connection %s terminated: Could not process PROXY header from client, " +
			"see previous log messages.", conn:ip());
		return;
	else
		-- This code should be never reached, but is included for completeness
		conn:close();
		module:log("warn", "Connection terminated: Received invalid protocol handler response with code %d", response);
		return;
	end
end

function listener.ondisconnect(conn)
	sessions[conn] = nil;
end

listener.ondetach = listener.ondisconnect;

-- Parse trusted proxies which can either contain single hosts or networks
if not config_trusted_proxies:empty() then
	for trusted_proxy in config_trusted_proxies:items() do
		local network = {};
		network.ip, network.cidr = ip.parse_cidr(trusted_proxy);
		trusted_networks:add(network);
	end
else
	module:log("warn", "No trusted proxies configured, all connections will be accepted - this might be dangerous");
end

-- Process all configured port mappings and generate a list of mapped ports
local mapped_ports = {};
for port, mapping in pairs(config_mappings) do
	port = tonumber(port);
	table.insert(mapped_ports, port);
	mappings[port] = {
		service_name = mapping,
		service = nil,
	};
end

-- Log error message when user manually specifies ports without configuring the necessary port mappings
if not config_ports:empty() then
	local missing_ports = config_ports - set.new(mapped_ports);
	if not missing_ports:empty() then
		module:log("error", "Missing port<>service mappings for these ports: %s", tostring(missing_ports));
	end
end

-- Register the previously declared network listener
module:provides("net", {
	name = "proxy";
	listener = listener;
	default_ports = mapped_ports;
});
