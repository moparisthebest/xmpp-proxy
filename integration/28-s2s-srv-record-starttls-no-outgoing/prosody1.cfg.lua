--Important for systemd
-- daemonize is important for systemd. if you set this to false the systemd startup will freeze.
daemonize = false
run_as_root = true

pidfile = "/run/prosody/prosody.pid"

plugin_paths = { "/opt/xmpp-proxy/prosody-modules", "/opt/prosody-modules" }

-- Prosody Example Configuration File
--
-- Information on configuring Prosody can be found on our
-- website at https://prosody.im/doc/configure
--
-- Tip: You can check that the syntax of this file is correct
-- when you have finished by running this command:
--     prosodyctl check config
-- If there are any errors, it will let you know what and where
-- they are, otherwise it will keep quiet.
--
-- The only thing left to do is rename this file to remove the .dist ending, and fill in the
-- blanks. Good luck, and happy Jabbering!


---------- Server-wide settings ----------
-- Settings in this section apply to the whole server and are the default settings
-- for any virtual hosts

-- This is a (by default, empty) list of accounts that are admins
-- for the server. Note that you must create the accounts separately
-- (see https://prosody.im/doc/creating_accounts for info)
-- Example: admins = { "user1@example.com", "user2@example.net" }
admins = { }

-- Enable use of libevent for better performance under high load
-- For more information see: https://prosody.im/doc/libevent
--use_libevent = true

-- Prosody will always look in its source directory for modules, but
-- this option allows you to specify additional locations where Prosody
-- will look for modules first. For community modules, see https://modules.prosody.im/
--plugin_paths = {}

-- This is the list of modules Prosody will load on startup.
-- It looks for mod_modulename.lua in the plugins folder, so make sure that exists too.
-- Documentation for bundled modules can be found at: https://prosody.im/doc/modules
modules_enabled = {

	-- Generally required
		"roster"; -- Allow users to have a roster. Recommended ;)
		"saslauth"; -- Authentication for clients and servers. Recommended if you want to log in.
		"tls"; -- Add support for secure TLS on c2s/s2s connections
		--"dialback"; -- s2s dialback support
		"disco"; -- Service discovery

	-- Not essential, but recommended
		"carbons"; -- Keep multiple clients in sync
		"pep"; -- Enables users to publish their avatar, mood, activity, playing music and more
		"private"; -- Private XML storage (for room bookmarks, etc.)
		"blocklist"; -- Allow users to block communications with other users
		"vcard4"; -- User profiles (stored in PEP)
		"vcard_legacy"; -- Conversion between legacy vCard and PEP Avatar, vcard
		"limits"; -- Enable bandwidth limiting for XMPP connections

	-- Nice to have
		"version"; -- Replies to server version requests
		"uptime"; -- Report how long server has been running
		"time"; -- Let others know the time here on this server
		"ping"; -- Replies to XMPP pings with pongs
		"register"; -- Allow users to register on this server using a client and change passwords
		--"mam"; -- Store messages in an archive and allow users to access it
		--"csi_simple"; -- Simple Mobile optimizations

	-- Admin interfaces
		"admin_adhoc"; -- Allows administration via an XMPP client that supports ad-hoc commands
		--"admin_telnet"; -- Opens telnet console interface on localhost port 5582

	-- HTTP modules
		--"bosh"; -- Enable BOSH clients, aka "Jabber over HTTP"
		--"websocket"; -- XMPP over WebSockets
		--"http_files"; -- Serve static files from a directory over HTTP

	-- Other specific functionality
		--"groups"; -- Shared roster support
		--"server_contact_info"; -- Publish contact information for this service
		--"announce"; -- Send announcement to all online users
		--"welcome"; -- Welcome users who register accounts
		--"watchregistrations"; -- Alert admins of registrations
		--"motd"; -- Send a message to users when they log in
		--"legacyauth"; -- Legacy authentication. Only used by some old clients and bots.
		--"proxy65"; -- Enables a file transfer proxy service which clients behind NAT can use
		"net_proxy";
		--"s2s_outgoing_proxy";
		"secure_interfaces";
}

-- These modules are auto-loaded, but should you want
-- to disable them then uncomment them here:
modules_disabled = {
	-- "offline"; -- Store offline messages
	-- "c2s"; -- Handle client connections
	-- "s2s"; -- Handle server-to-server connections
	-- "posix"; -- POSIX functionality, sends server to background, enables syslog, etc.
}

-- Disable account creation by default, for security
-- For more information see https://prosody.im/doc/creating_accounts
allow_registration = false

c2s_require_encryption = false
allow_unencrypted_plain_auth = true

s2s_require_encryption = true
s2s_secure_auth = true

-- handle PROXY protocol on these ports
proxy_port_mappings = {
    [15222] = "c2s",
    [15269] = "s2s"
}

--[[
  Specifies a list of trusted hosts or networks which may use the PROXY protocol
  If not specified, it will default to: 127.0.0.1, ::1 (local connections only)
  An empty table ({}) can be configured to allow connections from any source.
  Please read the module documentation about potential security impact.
]]-- 
proxy_trusted_proxies = {
    "192.5.0.40"
}

secure_interfaces = {
    "192.5.0.40"
}

-- don't listen on any normal c2s/s2s ports (xmpp-proxy listens on these now)
-- you might need to comment these out further down in your config file if you set them
c2s_ports = {}
legacy_ssl_ports = {}
-- you MUST have at least one s2s_ports defined if you want outgoing S2S to work, don't ask.. 
s2s_ports = {15268}


-- Some servers have invalid or self-signed certificates. You can list
-- remote domains here that will not be required to authenticate using
-- certificates. They will be authenticated using DNS instead, even
-- when s2s_secure_auth is enabled.

--s2s_insecure_domains = { "insecure.example" }

-- Even if you disable s2s_secure_auth, you can still require valid
-- certificates for some domains by specifying a list here.

--s2s_secure_domains = { "jabber.org" }

-- Enable rate limits for incoming client and server connections

limits = {
  c2s = {
    rate = "10kb/s";
  };
  s2sin = {
    rate = "30kb/s";
  };
}

-- Select the authentication backend to use. The 'internal' providers
-- use Prosody's configured data storage to store the authentication data.

authentication = "internal_hashed"

-- Select the storage backend to use. By default Prosody uses flat files
-- in its configured data directory, but it also supports more backends
-- through modules. An "sql" backend is included by default, but requires
-- additional dependencies. See https://prosody.im/doc/storage for more info.

--storage = "sql" -- Default is "internal"

-- For the "sql" backend, you can uncomment *one* of the below to configure:
--sql = { driver = "SQLite3", database = "prosody.sqlite" } -- Default. 'database' is the filename.
--sql = { driver = "MySQL", database = "prosody", username = "prosody", password = "secret", host = "localhost" }
--sql = { driver = "PostgreSQL", database = "prosody", username = "prosody", password = "secret", host = "localhost" }


-- Archiving configuration
-- If mod_mam is enabled, Prosody will store a copy of every message. This
-- is used to synchronize conversations between multiple clients, even if
-- they are offline. This setting controls how long Prosody will keep
-- messages in the archive before removing them.

archive_expires_after = "1w" -- Remove archived messages after 1 week

-- You can also configure messages to be stored in-memory only. For more
-- archiving options, see https://prosody.im/doc/modules/mod_mam

-- Logging configuration
-- For advanced logging see https://prosody.im/doc/logging
log = {
	-- info = "prosody.log"; -- Change 'info' to 'debug' for verbose logging
	-- error = "prosody.err";
	--info = "*syslog"; -- Uncomment this for logging to syslog
	debug = "*console"; -- Log to the console, useful for debugging with daemonize=false
}

-- Uncomment to enable statistics
-- For more info see https://prosody.im/doc/statistics
-- statistics = "internal"

-- Certificates
-- Every virtual host and component needs a certificate so that clients and
-- servers can securely verify its identity. Prosody will automatically load
-- certificates/keys from the directory specified here.
-- For more information, including how to use 'prosodyctl' to auto-import certificates
-- (from e.g. Let's Encrypt) see https://prosody.im/doc/certificates

-- Location of directory to find certificates in (relative to main config file):
certificates = "certs"

-- HTTPS currently only supports a single certificate, specify it here:
--https_certificate = "/etc/prosody/certs/localhost.crt"

----------- Virtual hosts -----------
-- You need to add a VirtualHost entry for each domain you wish Prosody to serve.
-- Settings under each VirtualHost entry apply *only* to that host.

VirtualHost "one.example.org"

--VirtualHost "example.com"
--	certificate = "/path/to/example.crt"

------ Components ------
-- You can specify components to add hosts that provide special services,
-- like multi-user conferences, and transports.
-- For more information on components, see https://prosody.im/doc/components

---Set up a MUC (multi-user chat) room server on conference.example.com:
--Component "conference.example.com" "muc"
--- Store MUC messages in an archive and allow users to access it
--modules_enabled = { "muc_mam" }

---Set up an external component (default component port is 5347)
--
-- External components allow adding various services, such as gateways/
-- transports to other networks like ICQ, MSN and Yahoo. For more info
-- see: https://prosody.im/doc/components#adding_an_external_component
--
--Component "gateway.example.com"
--	component_secret = "password"
