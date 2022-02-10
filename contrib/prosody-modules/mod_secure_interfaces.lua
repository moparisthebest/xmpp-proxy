local secure_interfaces = module:get_option_set("secure_interfaces", { "127.0.0.1", "::1" });

local function mark_secure(event, expected_type)
	local session = event.origin;
	if session.type ~= expected_type then return; end
	local socket = session.conn:socket();
	if not socket.getsockname then
		module:log("debug", "Unable to determine local address of incoming connection");
		return;
	end
	local localip = socket:getsockname();
	if secure_interfaces:contains(localip) then
		module:log("debug", "Marking session from %s to %s as secure", session.ip or "[?]", localip);
		session.secure = true;
		session.conn.starttls = false;
	else
		module:log("debug", "Not marking session from %s to %s as secure", session.ip or "[?]", localip);
	end
end

module:hook("stream-features", function (event)
	mark_secure(event, "c2s_unauthed");
end, 2500);

module:hook("s2s-stream-features", function (event)
	mark_secure(event, "s2sin_unauthed");
end, 2500);
