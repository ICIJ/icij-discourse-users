# name: icij-discourse-users
# about: A plugin for using groups to separate and organize categories and topics.
# version: 0.0.1
# authors: Madeline O'Leary

after_initialize do
  load File.expand_path('../serializers/icij_group_user_serializer.rb', __FILE__)

  require_dependency "user"
  class ::User
    def self.all_group_users(current_user)
      icij_group_ids = Group.icij_groups.pluck(:id)
      current_user_groups = current_user.group_users.where(group_id: icij_group_ids).pluck(:group_id)
      all_users_part_of_current_users_groups = GroupUser.where(group_id: current_user_groups).pluck(:user_id).uniq
      users = User.where(id: all_users_part_of_current_users_groups)

      users
    end

    def added_at
      ""
    end
  end

  require_dependency "application_controller"
  UsersController.class_eval do
    def all_users_in_groups
      users_to_display = User.all_group_users(current_user)
      render json: {
        members: serialize_data(users_to_display, IcijGroupUserSerializer)
      }
    end
  end

  require_dependency 'application_controller'
  Discourse::Application.routes.append do
    get "all-users-in-groups" => "users#all_users_in_groups"
  end
end