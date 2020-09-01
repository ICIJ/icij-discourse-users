# name: icij-discourse-users
# about: A plugin for using groups to separate and organize categories and topics.
# version: 0.0.1
# authors: Madeline O'Leary

after_initialize do

  User.register_custom_field_type("organization", :string)

  class ::User
    def organization_name
      self.custom_fields["organization"]
    end

    def self.filter_by_username_or_email_or_country(filter, current_user)
      if filter =~ /.+@.+/
        # probably an email so try the bypass
        if user_id = UserEmail.where("lower(email) = ?", filter.downcase).pluck(:user_id).first
          return where('users.id = ?', user_id)
        end
      end

      icij_group_ids = Group.icij_groups.pluck(:id)
      current_user_groups = current_user.group_users.where(group_id: icij_group_ids).pluck(:group_id)
      all_users_part_of_current_users_groups = GroupUser.where(group_id: current_user_groups).pluck(:user_id).uniq
      user_ids = User.where(id: all_users_part_of_current_users_groups).pluck(:id)

      users = joins(:primary_email)

      if filter.is_a?(Array)
        users.where(
          'username_lower ~* :filter OR lower(user_emails.email) SIMILAR TO :filter',
          filter: "(#{filter.join('|')})"
        ).where(id: user_ids)
      else
        users.where(
          'username_lower ILIKE :filter OR lower(user_emails.email) ILIKE :filter OR lower(country) ILIKE :filter',
          filter: "%#{filter}%"
        ).where(id: user_ids)
      end
    end

    def self.all_group_users(current_user)
      icij_group_ids = Group.icij_projects.pluck(:id)
      current_user_groups = current_user.group_users.where(group_id: icij_group_ids).pluck(:group_id)
      all_users_part_of_current_users_groups = GroupUser.where(group_id: current_user_groups).pluck(:user_id).uniq
      # users = User.where(id: all_users_part_of_current_users_groups).pluck(:id)

      users = User.where(id: all_users_part_of_current_users_groups)

      users
    end

    def added_at
      ""
    end
  end

  # Searches for a user by username or full text or name (if enabled in SiteSettings)
  class UserSearch
    def initialize(term, opts = {})
      @term = term
      @term_like = "#{term.downcase.gsub("_", "\\_")}%"
      @topic_id = opts[:topic_id]
      @topic_allowed_users = opts[:topic_allowed_users]
      @searching_user = opts[:searching_user]
      @include_staged_users = opts[:include_staged_users] || false
      @limit = opts[:limit] || 20
      @group = opts[:group]
      @guardian = Guardian.new(@searching_user)
      @guardian.ensure_can_see_group!(@group) if @group
    end

    def scoped_users
      users = User.where(active: true)
      users = users.where(staged: false) unless @include_staged_users

      if @group
        users = users.where('users.id IN (
          SELECT user_id FROM group_users WHERE group_id = ?
        )', @group.id)
      end

      unless @searching_user && @searching_user.staff?
        users = users.not_suspended
      end

      # Only show users who have access to private topic
      if @topic_id && @topic_allowed_users == "true"
        topic = Topic.find_by(id: @topic_id)

        if topic.category && topic.category.read_restricted
          users = users.includes(:secure_categories)
            .where("users.admin = TRUE OR categories.id = ?", topic.category.id)
            .references(:categories)
        end
      end

      users.limit(@limit)
    end

    def filtered_by_term_users
      users = scoped_users

      if @term.present?
        if SiteSetting.enable_names? && @term !~ /[_\.-]/
          # query = Search.ts_query(term: @term, ts_config: "simple")

          # why are they using this? the vector seems to take more time (did very rudimentary benchmark test)...maybe with thousands of users to search it starts to be faster? really not sure
          # users = users.includes(:user_search_data)
            # .references(:user_search_data)
            # .where("user_search_data.search_data @@ #{query}")
            # .order(DB.sql_fragment("CASE WHEN country LIKE ? THEN 0 ELSE 1 END ASC", @term_like, @term_like))

            # User.where("username ILIKE :term_like  OR country ILIKE :term_like", term_like: "%#{country}%").count
            users = users.where("username_lower ILIKE :term_like OR country ILIKE :term_like", term_like: @term_like)
        else
          users = users.where("username_lower LIKE :term_like OR country LIKE :term_like", term_like: @term_like)
        end
      end

      users
    end

    def search_ids
      users = Set.new

      # 1. exact username matches
      if @term.present?
        scoped_users.where(username_lower: @term.downcase)
          .limit(@limit)
          .pluck(:id)
          .each { |id| users << id }

      end

      return users.to_a if users.length >= @limit

      # 2. in topic
      if @topic_id
        filtered_by_term_users.where('users.id IN (SELECT p.user_id FROM posts p WHERE topic_id = ?)', @topic_id)
          .order('last_seen_at DESC')
          .limit(@limit - users.length)
          .pluck(:id)
          .each { |id| users << id }
      end

      return users.to_a if users.length >= @limit

      # 3. global matches
      filtered_by_term_users.order('last_seen_at DESC')
        .limit(@limit - users.length)
        .pluck(:id)
        .each { |id| users << id }

      users.to_a
    end

    def search
      ids = search_ids
      return User.where("0=1") if ids.empty?

      User.joins("JOIN (SELECT unnest uid, row_number() OVER () AS rn
        FROM unnest('{#{ids.join(",")}}'::int[])
      ) x on uid = users.id")
        .order("rn")
    end
  end

  class Auth::Result
    attr_accessor :user, :name, :username, :email, :user,
                  :email_valid, :country, :extra_data, :awaiting_activation,
                  :awaiting_approval, :authenticated, :authenticator_name,
                  :requires_invite, :not_allowed_from_ip_address,
                  :admin_not_allowed_from_ip_address, :omit_username,
                  :skip_email_validation, :destination_url, :omniauth_disallow_totp

    def session_data
      { email: email,
        username: username,
        country: country,
        email_valid: email_valid,
        omit_username: omit_username,
        name: name,
        authenticator_name: authenticator_name,
        extra_data: extra_data,
        skip_email_validation: !!skip_email_validation }
    end

    def to_client_hash
      if requires_invite
        { requires_invite: true }
      elsif user
        if user.suspended?
          {
            suspended: true,
            suspended_message: I18n.t(user.suspend_reason ? "login.suspended_with_reason" : "login.suspended",
                                       date: I18n.l(user.suspended_till, format: :date_only), reason: user.suspend_reason)
          }
        else
          result =
            if omniauth_disallow_totp
              {
                omniauth_disallow_totp: !!omniauth_disallow_totp,
                email: email
              }
            else
              {
                authenticated: !!authenticated,
                awaiting_activation: !!awaiting_activation,
                awaiting_approval: !!awaiting_approval,
                not_allowed_from_ip_address: !!not_allowed_from_ip_address,
                admin_not_allowed_from_ip_address: !!admin_not_allowed_from_ip_address
              }
            end

          result[:destination_url] = destination_url if authenticated && destination_url.present?
          result
        end
      else
        result = { email: email,
                   username: UserNameSuggester.suggest(username || name || email),
                   country: country,
                   # this feels a tad wrong
                   auth_provider: authenticator_name.capitalize,
                   email_valid: !!email_valid,
                   omit_username: !!omit_username }

        result[:destination_url] = destination_url if destination_url.present?

        if SiteSetting.enable_names?
          result[:name] = User.suggest_name(name || username || email)
        end

        result
      end
    end
  end

  class ::UserSerializer
    attributes :country, :organization_name
  end

  class ::DirectoryItemSerializer
    attributes :country,
              :user_created_at_age,
              :user_last_seen_age

    def country
      object.user.country
    end

    def user_created_at_age
      Time.now - object.user.created_at
      rescue
      nil
    end

    def user_last_seen_age
      return nil if object.user.last_seen_at.blank?
      Time.now - object.user.last_seen_at
      rescue
      nil
    end
  end

  SearchController.class_eval do
    def show
      @search_term = params.permit(:q)[:q]

      # a q param has been given but it's not in the correct format
      # eg: ?q[foo]=bar
      if params[:q].present? && !@search_term.present?
        raise Discourse::InvalidParameters.new(:q)
      end

      if @search_term.present? &&
         @search_term.length < SiteSetting.min_search_term_length
        raise Discourse::InvalidParameters.new(:q)
      end

      if @search_term.present? && @search_term.include?("\u0000")
        raise Discourse::InvalidParameters.new("string contains null byte")
      end

      search_args = {
        type_filter: 'topic',
        guardian: guardian,
        include_blurbs: true,
        blurb_length: 300,
        page: if params[:page].to_i <= 10
                [params[:page].to_i, 1].max
              end
      }

      context, type = lookup_search_context
      if context
        search_args[:search_context] = context
        search_args[:type_filter] = type if type
      end

      search_args[:search_type] = :full_page
      search_args[:ip_address] = request.remote_ip
      search_args[:user_id] = current_user.id if current_user.present?

      @search_term = params[:q]
      search = Search.new(@search_term, search_args)
      result = search.execute
      result.find_user_data(guardian) if result

      serializer = serialize_data(result, GroupedSearchResultSerializer, result: result)

      respond_to do |format|
        format.html do
          store_preloaded("search", MultiJson.dump(serializer))
        end
        format.json do
          render_json_dump(serializer)
        end
      end
    end
  end

  DirectoryItemsController.class_eval do
    PAGE_SIZE = 50

    def index
      raise Discourse::InvalidAccess.new(:enable_user_directory) unless SiteSetting.enable_user_directory?

      period_type = 5
      raise Discourse::InvalidAccess.new(:period_type) unless period_type

      if current_user
        groups = current_user.groups.where(icij_group: true).pluck(:group_id)
        users = GroupUser.where(group_id: groups).pluck(:user_id).uniq
        result = DirectoryItem.where(period_type: period_type).includes(:user).where(user_id: users)
      else
        result = DirectoryItem.where(period_type: period_type).includes(:user)
      end

      if params[:group]
        result = result.includes(user: :groups).where(users: { groups: { name: params[:group] } })
      end

      if params[:exclude_usernames]
        result = result.references(:user).where.not(users: { username: params[:exclude_usernames].split(",") })
      end

      order = params[:order] || DirectoryItem.headings.first
      if DirectoryItem.headings.include?(order.to_sym)
        dir = params[:asc] ? 'ASC' : 'DESC'
        result = result.order("directory_items.#{order} #{dir}")
      end

      if period_type == DirectoryItem.period_types[:all]
        result = result.includes(:user_stat)
      end
      page = params[:page].to_i

      user_ids = nil
      if params[:name].present?
        user_ids = UserSearch.new(params[:name], include_staged_users: true).search.pluck(:id)
        if user_ids.present?
          # Add the current user if we have at least one other match
          # if current_user && result.dup.where(user_id: user_ids).exists?
          #   user_ids << current_user.id
          # end
          result = result.where(user_id: user_ids)
        else
          result = result.where('false')
        end
      end

      if params[:username]
        user_id = User.where(username_lower: params[:username].to_s.downcase).pluck(:id).first
        if user_id
          result = result.where(user_id: user_id)
        else
          result = result.where('false')
        end
      end

      result_count = result.count
      result = result.limit(PAGE_SIZE).offset(PAGE_SIZE * page).to_a

      more_params = params.slice(:period, :order, :asc).permit!
      more_params[:page] = page + 1

      # Put yourself at the top of the first page
      if result.present? && current_user.present? && page == 0

        position = result.index { |r| r.user_id == current_user.id }

        # Don't show the record unless you're not in the top positions already
        if (position || 10) >= 10
          your_item = DirectoryItem.where(period_type: period_type, user_id: current_user.id).first
          result.insert(0, your_item) if your_item
        end

      end

      render_json_dump(directory_items: serialize_data(result, DirectoryItemSerializer),
                       total_rows_directory_items: result_count,
                       load_more_directory_items: directory_items_path(more_params))
    end
  end

  UsersController.class_eval do
    HONEYPOT_KEY ||= 'HONEYPOT_KEY'
    CHALLENGE_KEY ||= 'CHALLENGE_KEY'

    def create
      params.require(:email)
      params.require(:username)
      params.permit(:user_fields)

      unless SiteSetting.allow_new_registrations
        return fail_with("login.new_registrations_disabled")
      end

      if params[:password] && params[:password].length > User.max_password_length
        return fail_with("login.password_too_long")
      end

      if params[:email].length > 254 + 1 + 253
        return fail_with("login.email_too_long")
      end

      if clashing_with_existing_route?(params[:username]) || User.reserved_username?(params[:username])
        return fail_with("login.reserved_username")
      end

      params[:locale] ||= I18n.locale unless current_user

      new_user_params = user_params.except(:timezone)
      user = User.unstage(new_user_params)
      # unknown attribute timezone causing problem here
      user = User.new(new_user_params) if user.nil?

      # Handle API approval
      ReviewableUser.set_approved_fields!(user, current_user) if user.approved?

      # Handle custom fields
      user_fields = UserField.all
      if user_fields.present?
        field_params = params[:user_fields] || {}
        fields = user.custom_fields

        user_fields.each do |f|
          field_val = field_params[f.id.to_s]
          if field_val.blank?
            return fail_with("login.missing_user_field") if f.required?
          else
            fields["#{User::USER_FIELD_PREFIX}#{f.id}"] = field_val[0...UserField.max_length]
          end
        end

        user.custom_fields = fields
      end

      authentication = UserAuthenticator.new(user, session)

      if !authentication.has_authenticator? && !SiteSetting.enable_local_logins
        return render body: nil, status: :forbidden
      end

      authentication.start

      if authentication.email_valid? && !authentication.authenticated?
        # posted email is different that the already validated one?
        return fail_with('login.incorrect_username_email_or_password')
      end

      activation = UserActivator.new(user, request, session, cookies)
      activation.start

      # just assign a password if we have an authenticator and no password
      # this is the case for Twitter
      user.password = SecureRandom.hex if user.password.blank? && authentication.has_authenticator?
      if !session[:authentication][:country].nil?
        user.country = session[:authentication][:country]
      end

      if !session[:authentication][:organization].present?
        user.custom_fields["organization"] = session[:authentication][:organization]
      end

      if user.save

        authentication.finish
        activation.finish
        user.update_timezone_if_missing(params[:timezone])

        secure_session[HONEYPOT_KEY] = nil
        secure_session[CHALLENGE_KEY] = nil

        render json: {
          success: true,
          active: true,
          message: activation.message,
          user_id: user.id
        }
      elsif SiteSetting.hide_email_address_taken && user.errors[:primary_email]&.include?(I18n.t('errors.messages.taken'))
        session["user_created_message"] = activation.success_message

        if existing_user = User.find_by_email(user.primary_email&.email)
          Jobs.enqueue(:critical_user_email, type: :account_exists, user_id: existing_user.id)
        end

        render json: {
          success: true,
          active: true,
          message: activation.success_message,
          user_id: user.id
        }
      else
        errors = user.errors.to_hash
        errors[:email] = errors.delete(:primary_email) if errors[:primary_email]

        render json: {
          success: false,
          message: I18n.t(
            'login.errors',
            errors: user.errors.full_messages.join("\n")
          ),
          errors: errors,
          values: {
            name: user.name,
            username: user.username,
            email: user.primary_email&.email
          },
          is_developer: UsernameCheckerService.is_developer?(user.email)
        }
      end
    rescue ActiveRecord::StatementInvalid
      render json: {
        success: false,
        message: I18n.t("login.something_already_taken")
      }
    end

    private

    def user_params
      permitted = [
        :name,
        :email,
        :password,
        :country,
        :username,
        :title,
        :date_of_birth,
        :muted_usernames,
        :ignored_usernames,
        :theme_ids,
        :locale,
        :bio_raw,
        :location,
        :website,
        :dismissed_banner_key,
        :profile_background_upload_url,
        :card_background_upload_url,
        :primary_group_id,
        :featured_topic_id
      ]

      editable_custom_fields = User.editable_user_custom_fields(by_staff: current_user.try(:staff?))
      permitted << { custom_fields: editable_custom_fields } unless editable_custom_fields.blank?
      permitted.concat UserUpdater::OPTION_ATTR
      permitted.concat UserUpdater::CATEGORY_IDS.keys.map { |k| { k => [] } }
      permitted.concat UserUpdater::TAG_NAMES.keys

      result = params
        .permit(permitted, theme_ids: [])
        .reverse_merge(
          ip_address: request.remote_ip,
          registration_ip_address: request.remote_ip
        )

      if !UsernameCheckerService.is_developer?(result['email']) &&
          is_api? &&
          current_user.present? &&
          current_user.admin?

        result.merge!(params.permit(:active, :staged, :approved))
      end

      modify_user_params(result)
    end
  end

  class ::Search
    def find_grouped_results
      if @results.type_filter.present?
        raise Discourse::InvalidAccess.new("invalid type filter") unless Search.facets.include?(@results.type_filter)
        send("#{@results.type_filter}_search")
      else
        unless @search_context
          user_search if @term.present?
          user_country_search if @term.present?
          category_search if @term.present?
          tags_search if @term.present?
        end
        topic_search
      end

      add_more_topics_if_expected
      @results
    rescue ActiveRecord::StatementInvalid
      # In the event of a PG:Error return nothing, it is likely they used a foreign language whose
      # locale is not supported by postgres
    end

    private

    def user_country_search
      return if SiteSetting.hide_user_profiles_from_public && !@guardian.user

      users = User.includes(:user_search_data)
        .references(:user_search_data)
        .where(active: true)
        .where(staged: false)
        .where("country ILIKE ?", "%#{@original_term}%")

      users.each do |user|
        @results.add(user)
      end
    end
  end

  class ::BasicUserSerializer
    attributes :country
    
    def country
      user.country
      rescue
      user.try(:country)
    end
  end

  class ::AdminUserListSerializer
    attributes :country

    def country
      user.country
      rescue
      user.try(:country)
    end
  end

  class ::SearchResultUserSerializer
    attributes :country

    def country
      user.country
      rescue
      user.try(:country)
    end
  end
end
