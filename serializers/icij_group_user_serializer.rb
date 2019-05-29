class IcijGroupUserSerializer < ApplicationSerializer
  attributes :title, :last_posted_at, :last_seen_at, :added_at, :id, :username, :name, :country, :avatar_template

  def name
    Hash === user ? user[:name] : user.try(:name)
  end

  def include_name?
    SiteSetting.enable_names?
  end

  def avatar_template
    if Hash === object
      User.avatar_template(user[:username], user[:uploaded_avatar_id])
    else
      user&.avatar_template
    end
  end

  def user
    object[:user] || object
  end

  def include_added_at
    object.respond_to? :added_at
  end
end
