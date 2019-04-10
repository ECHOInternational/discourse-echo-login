# name: ECHO Login
# about: Current User Modifications to use ECHOcommunity Cookies to log in users.
# version: 1.8.2
# authors: Nate Flood for ECHO Inc

require_dependency 'single_sign_on'
require_dependency "auth/current_user_provider"
require_dependency "rate_limiter"
require_dependency "app/models/user_auth_token"
require_dependency "app/models/discourse_single_sign_on"

# This section monkey patches the Single Sign on Provider to provide the current url instead
# of doing all of the sso functions we don't really need since we're using cookies to set
# the current user.
after_initialize do 
  SingleSignOn.class_eval do
    def to_url(base_url=nil)
      "#{SiteSetting.sso_url}/?return_path=#{(ERB::Util.url_encode(Discourse.base_url + return_path))}"
    end
  end
end

class ECHOcommunityCurrentUserProvider < Auth::CurrentUserProvider

  CURRENT_USER_KEY ||= "_DISCOURSE_CURRENT_USER".freeze
  API_KEY ||= "api_key".freeze
  USER_API_KEY ||= "HTTP_USER_API_KEY".freeze
  USER_API_CLIENT_ID ||= "HTTP_USER_API_CLIENT_ID".freeze
  API_KEY_ENV ||= "_DISCOURSE_API".freeze
  USER_API_KEY_ENV ||= "_DISCOURSE_USER_API".freeze

  #modify to match the configuration for the rest of the site
  TOKEN_COOKIE ||= ENV['TOKEN_COOKIE']
  SESSION_NAMESPACE ||= ENV['SESSION_NAMESPACE']

  IMPERSONATE_COOKIE ||= "_forum_admin_impersonate"
  IMPERSONATE_LENGTH ||= 10800

  PATH_INFO ||= "PATH_INFO".freeze
  COOKIE_ATTEMPTS_PER_MIN ||= 10

  USER_DB_REDIS_HOST ||= ENV['USER_DB_REDIS_HOST']
  USER_DB_REDIS_PORT ||= ENV['USER_DB_REDIS_PORT']


  # Our Modification
  @@user_db = Redis.new(:host => USER_DB_REDIS_HOST, :port =>USER_DB_REDIS_PORT)

  def initialize(env)
    @env = env
    @request = Rack::Request.new(env)
  end

  # our current user, return nil if none is found
  def current_user
    return @env[CURRENT_USER_KEY] if @env.key?(CURRENT_USER_KEY)

    # bypass if we have the shared session header
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

    user_api_key = @env[USER_API_KEY]
    api_key = request[API_KEY]

    auth_token = request.cookies[TOKEN_COOKIE] unless user_api_key || api_key

    current_user = nil
    apex_session = nil

    if auth_token && current_user.nil?
      # get user's details from the redis store
      apex_session = @@user_db.get "#{SESSION_NAMESPACE}:#{auth_token}"
    end

    apex_user = nil

    if apex_session
      unmarshaled_session_data =  Marshal.load(apex_session)
      apex_user = {}
      apex_user["email_address"] = unmarshaled_session_data["warden.user.user.email"]
      apex_user["first_name"] = unmarshaled_session_data["warden.user.user.first_name"]
      apex_user["last_name"] = unmarshaled_session_data["warden.user.user.last_name"]
      apex_user["nickname"] = unmarshaled_session_data["warden.user.user.nickname"]
      apex_user["nickname"] = "#{apex_user['first_name']} #{apex_user['last_name']}" if apex_user["nickname"].blank?
      apex_user["avatar_url"] = unmarshaled_session_data["warden.user.user.headshot_url"]
      apex_user["role"] = unmarshaled_session_data["warden.user.user.role"]
      apex_user["uid"] = unmarshaled_session_data["warden.user.user.uid"]
    end

    if apex_user && apex_user["uid"]
      sso = DiscourseSingleSignOn.new
      sso.email = apex_user["email_address"]
      sso.name = apex_user["nickname"]
      sso.username = apex_user["nickname"]
      sso.require_activation = false
      sso.suppress_welcome_message = true
      sso.external_id = apex_user["uid"]
      sso.admin = apex_user["role"] == "ECHOstaff" ? true : false
      sso.moderator = apex_user["role"] == "ECHOstaff" ? true : false
      # unless apex_user["avatar_url"].blank?
      #   sso.avatar_url = apex_user["avatar_url"]
      #   sso.avatar_force_update = true
      # end

      current_user = sso.lookup_or_create_user
    end

    if current_user && should_update_last_seen?
      u = current_user
      Scheduler::Defer.later "Updating Last Seen" do
        u.update_last_seen!
        u.update_ip_address!(request.ip)
      end
    end

    # possible we have an api call, impersonate
    if api_key
      current_user = lookup_api_user(api_key, request)
      raise Discourse::InvalidAccess unless current_user
      raise Discourse::InvalidAccess if current_user.suspended? || !current_user.active
      @env[API_KEY_ENV] = true
    end

    # user api key handling
    if user_api_key

      limiter_min = RateLimiter.new(nil, "user_api_min_#{user_api_key}", SiteSetting.max_user_api_reqs_per_minute, 60)
      limiter_day = RateLimiter.new(nil, "user_api_day_#{user_api_key}", SiteSetting.max_user_api_reqs_per_day, 86400)

      unless limiter_day.can_perform?
        limiter_day.performed!
      end

      unless  limiter_min.can_perform?
        limiter_min.performed!
      end

      current_user = lookup_user_api_user_and_update_key(user_api_key, @env[USER_API_CLIENT_ID])
      raise Discourse::InvalidAccess unless current_user
      raise Discourse::InvalidAccess if current_user.suspended? || !current_user.active

      limiter_min.performed!
      limiter_day.performed!

      @env[USER_API_KEY_ENV] = true
    end

    # keep this rule here as a safeguard
    # under no conditions to suspended or inactive accounts get current_user
    if current_user && (current_user.suspended? || !current_user.active)
      current_user = nil
    end

    if request.cookies[IMPERSONATE_COOKIE]
      user_id = @@user_db.get "#{SESSION_NAMESPACE}_impersonate:#{request.cookies[IMPERSONATE_COOKIE]}"
      impersonated_user = User.find(user_id) if user_id
      
      current_user = impersonated_user if impersonated_user
    end

    @env[CURRENT_USER_KEY] = current_user
  end

  # This is only used for impersonate.
  def log_on_user(user, session, cookies, opts = {})
    impersonate_key = SecureRandom.hex(12)
    @@user_db.set("#{SESSION_NAMESPACE}_impersonate:#{impersonate_key}", user.id, {ex: IMPERSONATE_LENGTH})
    cookies[IMPERSONATE_COOKIE] = impersonate_key
    user
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

  def enable_bootstrap_mode(user)
    Jobs.enqueue(:enable_bootstrap_mode, user_id: user.id) if user.admin && user.last_seen_at.nil? && !SiteSetting.bootstrap_mode_enabled && user.is_singular_admin?
  end

  def log_off_user(session, cookies)
    # If we're impersonating, stop, and leave the user logged in.
    if cookies[IMPERSONATE_COOKIE]
      @@user_db.del "#{SESSION_NAMESPACE}_impersonate:#{cookies[IMPERSONATE_COOKIE]}"
      cookies.delete(IMPERSONATE_COOKIE)
      return true
    end

    user = current_user
    if SiteSetting.log_out_strict && user
      user.user_auth_tokens.destroy_all

      if user.admin && defined?(Rack::MiniProfiler)
        # clear the profiling cookie to keep stuff tidy
        cookies.delete("__profilin")
      end

      user.logged_out
    elsif user && @user_token
      @user_token.destroy
    end
    
    @@user_db.del "#{SESSION_NAMESPACE}:#{cookies[TOKEN_COOKIE]}"
    cookies.delete("remember_user_token", :domain => ".echocommunity.org")
    cookies.delete(TOKEN_COOKIE, :domain => ".echocommunity.org")
  end


  # api has special rights return true if api was detected
  def is_api?
    current_user
    !!(@env[API_KEY_ENV])
  end

  def is_user_api?
    current_user
    !!(@env[USER_API_KEY_ENV])
  end

  def has_auth_cookie?
    cookie = @request.cookies[TOKEN_COOKIE]
    !cookie.nil? && cookie.length == 32
  end

  def should_update_last_seen?
    if @request.xhr?
      @env["HTTP_DISCOURSE_VISIBLE".freeze] == "true".freeze
    else
      true
    end
  end

  protected

  def lookup_user_api_user_and_update_key(user_api_key, client_id)
    if api_key = UserApiKey.where(key: user_api_key, revoked_at: nil).includes(:user).first
      unless api_key.allow?(@env)
        raise Discourse::InvalidAccess
      end

      if client_id.present? && client_id != api_key.client_id
        api_key.update_columns(client_id: client_id)
      end

      api_key.user
    end
  end

  def lookup_api_user(api_key_value, request)
    if api_key = ApiKey.where(key: api_key_value).includes(:user).first
      api_username = request["api_username"]

      if api_key.allowed_ips.present? && !api_key.allowed_ips.any? { |ip| ip.include?(request.ip) }
        Rails.logger.warn("[Unauthorized API Access] username: #{api_username}, IP address: #{request.ip}")
        return nil
      end

      if api_key.user
        api_key.user if !api_username || (api_key.user.username_lower == api_username.downcase)
      elsif api_username
        User.find_by(username_lower: api_username.downcase)
      end
    end
  end

end

Discourse.current_user_provider = ECHOcommunityCurrentUserProvider