local st = require"util.stanza";
local new_ip = require"util.ip".new_ip;
local new_outgoing = require"core.s2smanager".new_outgoing;
local bounce_sendq = module:depends"s2s".route_to_new_session.bounce_sendq;
local s2sout = module:depends"s2s".route_to_new_session.s2sout;

local s2s_outgoing_proxy = module:get_option("s2s_outgoing_proxy");

module:hook("route/remote", function(event)
	local from_host, to_host, stanza = event.from_host, event.to_host, event.stanza;
	log("debug", "opening a new outgoing connection for this stanza");
	local host_session = new_outgoing(from_host, to_host);
	host_session.version = 1;

	-- Store in buffer
	host_session.bounce_sendq = bounce_sendq;
	host_session.sendq = { {tostring(stanza), stanza.attr.type ~= "error" and stanza.attr.type ~= "result" and st.reply(stanza)} };
	log("debug", "stanza [%s] queued until connection complete", tostring(stanza.name));

	local ip_hosts = {};

    local host, port = s2s_outgoing_proxy[1] or s2s_outgoing_proxy, tonumber(s2s_outgoing_proxy[2]) or 15270;
	ip_hosts[#ip_hosts+1] = { ip = new_ip(host), port = port }

	host_session.ip_hosts = ip_hosts;
	host_session.ip_choice = 0; -- Incremented by try_next_ip
	s2sout.try_next_ip(host_session);
	return true;
end, -2);

-- is this the best place to do this?
module:hook_tag("http://etherx.jabber.org/streams", "features", function (session, stanza)
	if session.type == "s2sout_unauthed" then
        module:log("debug", "marking hook session.type '%s' secure!", session.type);
        session.secure = true;
	end
end, 3000);
