# name: ECHO Login
# about: Current User Modifications to use ECHOcommunity Cookies to log in users.
# version: 0.0.1
# authors: Nate Flood for ECHO Inc

# This section monkey patches the Single Sign on Provider to provide the current url instead
# of doing all of the sso functions we don't really need since we're using cookies to set
# the session and current user.
after_initialize do 
  DiscourseSingleSignOn.class_eval do
    def self.generate_url(return_path="/")
      "#{SiteSetting.sso_url}/#{CGI.escape(Discourse.base_url + return_path)}"
    end
  end
end



class ECHOcommunityCurrentUserProvider < Auth::CurrentUserProvider

  CURRENT_USER_KEY ||= "_DISCOURSE_CURRENT_USER".freeze
  API_KEY ||= "api_key".freeze
  API_KEY_ENV ||= "_DISCOURSE_API".freeze

  #modify to match the configuration for the rest of the site
  #TODO: Make this a configuration setting
  TOKEN_COOKIE ||= "_ECHOcommunity_session".freeze
  SESSION_NAMESPACE ||= "session".freeze

  PATH_INFO ||= "PATH_INFO".freeze


  def initialize(env)
    @env = env
    @request = Rack::Request.new(env)
    # TODO: Make these configuration variables
    @user_db = Redis.new(:host => "localhost", :port => 6379)
  end

  # our current user, return nil if none is found
  def current_user
    # If there is already a current user key in the @env variable
    # skip the rest of this method and return that user key.
    return @env[CURRENT_USER_KEY] if @env.key?(CURRENT_USER_KEY)


    # bypass if we have the shared session header
    # this header would be set by the site's CDN 
    # removing this block might break the messaging bus
    # when using a CDN
    if shared_key = @env['HTTP_X_SHARED_SESSION_KEY']
      uid = $redis.get("shared_session_key_#{shared_key}")
      user = nil
      if uid
        user = User.find_by(id: uid.to_i)
      end
      @env[CURRENT_USER_KEY] = user
      return user
    end

    request = @request
    auth_token = request.cookies[TOKEN_COOKIE]

    current_user = nil

    # if there is a valid auth token, figure out who it belongs to (if anyone)
    if auth_token && auth_token.length == 32
      # does a user have this auth token assigned to them?
      # if yes return them (if not you'll get nil)
      current_user = User.find_by(auth_token: auth_token)
    end

    apex_session = nil

    if auth_token && current_user.nil?
      # get user's details from the redis store
      apex_session = @user_db.get "#{SESSION_NAMESPACE}:#{auth_token}"
    end

    apex_user = nil

    if apex_session

    end

    if apex_user
    	# see if a user with that email address already has an account
    	# if not create one for them
    	
    	# user = User.find_or_create_by(foreign_id: apex_user['foreign_id'])

    	# update the details on that account
    	# user.attribute = apex_user.attribute

    	# By writing the auth token to the user we save ourselves
    	# the round trip to the redis server
    	user.auth_token = auth_token

    	user.save!
    	current_user = user
    end

    if current_user && (current_user.suspended? || !current_user.active)
      # pretend there is no user even if one is found, if that user is inactive or 
      # suspended.
      current_user = nil
    end

    if current_user && should_update_last_seen?
      # touch the user to change last seen date (so long as the request
      # isn't coming from the messaging bus)
      u = current_user
      Scheduler::Defer.later "Updating Last Seen" do
        u.update_last_seen!
        u.update_ip_address!(request.ip)
      end
    end

    # possible we have an api call, impersonate
    # if request[API_KEY] is not nil, assign its value to api_key and
    if api_key = request[API_KEY]

      current_user = lookup_api_user(api_key, request)
      raise Discourse::InvalidAccess unless current_user
      @env[API_KEY_ENV] = true
    end

    # Set the environment variable to contain the current user object
    # and return that user object to the caller
    @env[CURRENT_USER_KEY] = current_user
  end

  def log_on_user(user, session, cookies)
  	# This is only currently used by the Impersonate function
  	# This overwrites the auth token cookie with one stored in
  	# the user record of the user we're trying to impersonate
  	# (and that field will be created if it doesn't exist)
  	# This will log out the user that was logged in (both here
  	# and on all other services on this domain. Unfortunate, but
  	# not unacceptable side effect)

    # does the user record have an auth token string? Is it the right length?
    unless user.auth_token && user.auth_token.length == 32
      # no? Ok add one
      user.auth_token = SecureRandom.hex(16)
      # and update the record
      user.save!
    end

    # create a session cookie that is the same as the user's auth_token
    cookies.permanent[TOKEN_COOKIE] = { value: user.auth_token, httponly: true }


    make_developer_admin(user)

    # make the env current user the same one logged in
    @env[CURRENT_USER_KEY] = user
  end

  def make_developer_admin(user)
    if  user.active? &&
        !user.admin &&
        Rails.configuration.respond_to?(:developer_emails) &&
        Rails.configuration.developer_emails.include?(user.email)
      user.admin = true
      user.save
    end
  end

  def log_off_user(session, cookies)
    if SiteSetting.log_out_strict && (user = current_user)
      # Erase the saved token
      user.auth_token = nil
      user.save!
      # Notify the pubsub server
      MessageBus.publish "/logout", user.id, user_ids: [user.id]
    end

    # TODO: Destroy the session in the redis server

    # erase the matching cookie
    cookies[TOKEN_COOKIE] = nil
  end


  # api has special rights return true if api was detected
  def is_api?
    # this method modifies the @env[API_KEY_ENV] variable
    current_user
    # it will be false if not an api call, true if it is.
    @env[API_KEY_ENV]
  end

  def has_auth_cookie?
    # Just checks for a cookie of the expected length
    cookie = @request.cookies[TOKEN_COOKIE]
    !cookie.nil? && cookie.length == 32
  end

  def should_update_last_seen?
    # Not if the message bus is the one calling, that would keep it around forever.
    !(@request.path =~ /^\/message-bus\//)
  end

  protected

  def lookup_api_user(api_key_value, request)
    # Query the ApiKey model and get the associated user record as well
    api_key = ApiKey.where(key: api_key_value).includes(:user).first

    # only if something is in the query
    if api_key
      # get the username supplied with the request
      api_username = request["api_username"]

      # check that the api can be called from the address it was called from.
      if api_key.allowed_ips.present? && !api_key.allowed_ips.any?{|ip| ip.include?(request.ip)}
        Rails.logger.warn("Unauthorized API access: #{api_username} ip address: #{request.ip}")
        return nil
      end

      # does this apikey have an associated user? no? what will you get as a response? False?
      # Not exactly sure what it is returning, always a user object anyway... Have to read up
      # on the api implementation.
      if api_key.user
        api_key.user if !api_username || (api_key.user.username_lower == api_username.downcase)
      elsif api_username
        User.find_by(username_lower: api_username.downcase)
      end
    end
  end

end



# Discourse.current_user_provider = ECHOcommunityCurrentUserProvider