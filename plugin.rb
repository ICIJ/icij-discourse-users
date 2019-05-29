# name: icij-discourse-users
# about: A plugin for using groups to separate and organize categories and topics.
# version: 0.0.1
# authors: Madeline O'Leary

register_asset "stylesheets/icij-users-list.scss"

after_initialize do
  require_dependency "user"
  class ::User
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

  require_dependency "../lib/auth/result"
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


  require_dependency "application_controller"
  require_dependency "../../lib/icij_user_index_query"
  UsersController.class_eval do
    def create
      params.require(:email)
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

      if User.reserved_username?(params[:username])
        return fail_with("login.reserved_username")
      end

      new_user_params = user_params
      user = User.unstage(new_user_params)
      user = User.new(new_user_params) if user.nil?

      # Handle API approval
      if user.approved
        user.approved_by_id ||= current_user.id
        user.approved_at ||= Time.zone.now
      end

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

      if user.save
        authentication.finish
        activation.finish

        # save user email in session, to show on account-created page
        session["user_created_message"] = activation.message
        session[SessionController::ACTIVATE_USER_KEY] = user.id

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

    def icij_users_list
      users = ::IcijUserIndexQuery.new(params).find_users(current_user)

      render_serialized(users, AdminUserListSerializer)
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
        :theme_ids,
        :locale,
        :bio_raw,
        :location,
        :website,
        :dismissed_banner_key,
        :profile_background,
        :card_background
      ]

      permitted << { custom_fields: User.editable_user_custom_fields } unless User.editable_user_custom_fields.blank?
      permitted.concat UserUpdater::OPTION_ATTR
      permitted.concat UserUpdater::CATEGORY_IDS.keys.map { |k| { k => [] } }
      permitted.concat UserUpdater::TAG_NAMES.keys

      result = params
        .permit(permitted, theme_ids: [])
        .reverse_merge(
          ip_address: request.remote_ip,
          registration_ip_address: request.remote_ip,
          locale: user_locale
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

  require_dependency "../lib/search"
  require_dependency "../lib/search/grouped_search_results"
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

  require_dependency 'basic_user_serializer'
  class ::BasicUserSerializer
    attributes :country

    def country
      user.country
      rescue
      user.try(:country)
    end
  end

  require_dependency 'admin_user_list_serializer'
  class ::AdminUserListSerializer
    attributes :country

    def country
      user.country
      rescue
      user.try(:country)
    end
  end

  require_dependency 'search_result_user_serializer'
  class ::SearchResultUserSerializer
    attributes :country

    def country
      user.country
      rescue
      user.try(:country)
    end
  end

  require_dependency "application_controller"
  Discourse::Application.routes.append do
    get "icij-users-list" => "users#icij_users_list"
  end
end
