--% requires: s2sout-pre-connect-event

local basic_resolver = require "net.resolvers.basic";

local s2s_outgoing_proxy = module:get_option("s2s_outgoing_proxy");

local host, port = s2s_outgoing_proxy[1] or s2s_outgoing_proxy, tonumber(s2s_outgoing_proxy[2]) or 15270;

module:hook("s2sout-pre-connect", function (event)
	local session = event.session;
	local to_host = session.to_host;

    -- mark it secure so we will offer SASL EXTERNAL auth
    session.secure = true;

	event.resolver = basic_resolver.new(host, port, "tcp");
end);

-- todo: is this the best place to do this hook?
-- this hook marks incoming s2s as secure so we offer SASL EXTERNAL auth
module:hook("s2s-stream-features", function(event)
	local session, features = event.origin, event.features;
	if session.type == "s2sin_unauthed" then
        module:log("debug", "marking hook session.type '%s' secure with validated cert!", session.type);
	    session.secure = true;
    	session.cert_chain_status = "valid";
    	session.cert_identity_status = "valid";
    end
end, 3000);
