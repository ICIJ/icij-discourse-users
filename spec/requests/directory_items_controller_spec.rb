require 'rails_helper'

describe DirectoryItemsController do
  let!(:user) { Fabricate(:user) }
  let!(:evil_trout) { Fabricate(:evil_trout) }
  let!(:walter_white) { Fabricate(:walter_white) }
  let!(:stage_user) { Fabricate(:staged, username: 'stage_user') }
  let!(:group) { Fabricate(:icij_group, users: [evil_trout, user]) }
  let!(:another_group) { Fabricate(:icij_group, users: [walter_white, stage_user]) }

  it "does not require a `period` param" do
    get '/directory_items.json'
    expect(response.status).to eq(200)
  end

  context "without data" do
    context "and a logged in user" do
      before { sign_in(user) }

      it "succeeds" do
        get '/directory_items.json', params: { period: 'all' }
        expect(response.status).to eq(200)
      end
    end
  end

  context "with data" do
    before do
      DirectoryItem.refresh!
    end

    it "succeeds with a valid value" do
      get '/directory_items.json', params: { period: 'all' }
      expect(response.status).to eq(200)
      json = ::JSON.parse(response.body)

      expect(json).to be_present
      expect(json['directory_items']).to be_present
      expect(json['total_rows_directory_items']).to be_present
      expect(json['load_more_directory_items']).to be_present

      expect(json['directory_items'].length).to eq(4)
      expect(json['total_rows_directory_items']).to eq(4)
    end

    it "fails when the directory is disabled" do
      SiteSetting.enable_user_directory = false

      get '/directory_items.json', params: { period: 'all' }
      expect(response).not_to be_successful
    end

    context "signed-in user belongs to icij project group" do
      before do
        DirectoryItem.refresh!
        sign_in(user)
      end

      it "finds user by name" do
        get '/directory_items.json', params: { period: 'all', name: 'eviltrout' }
        expect(response.status).to eq(200)

        json = ::JSON.parse(response.body)
        expect(json).to be_present
        expect(json['directory_items'].length).to eq(2)
        expect(json['total_rows_directory_items']).to eq(1)
        expect(json['directory_items'][1]['user']['username']).to eq('eviltrout')
      end

      it "does not find user by name, if that user is not a project group member" do
        get '/directory_items.json', params: { period: 'all', name: 'Walter White' }
        expect(response.status).to eq(200)

        json = ::JSON.parse(response.body)
        expect(json).to be_present
        expect(json['directory_items'].length).to eq(0)
        expect(json['total_rows_directory_items']).to eq(0)
      end

      it "excludes users by username" do
        get '/directory_items.json', params: { period: 'all', exclude_usernames: "eviltrout" }
        expect(response.status).to eq(200)

        json = ::JSON.parse(response.body)
        expect(json).to be_present
        expect(json['directory_items'].length).to eq(1)
        expect(json['total_rows_directory_items']).to eq(1)
        expect(json['directory_items'][0]['user']['username']).to eq(user.username)
      end

      it "filters users by group for the user's project groups" do
        get '/directory_items.json', params: { period: 'all', group: group.name }
        expect(response.status).to eq(200)

        json = ::JSON.parse(response.body)
        expect(json).to be_present
        expect(json['directory_items'].length).to eq(2)
        expect(json['total_rows_directory_items']).to eq(2)
        expect(json['directory_items'][0]['user']['username']).to eq(evil_trout.username)
        expect(json['directory_items'][1]['user']['username']).to eq(user.username)
      end

      it "does not filter users for project groups to which the user is not a member" do
        get '/directory_items.json', params: { period: 'all', group: another_group.name }
        expect(response.status).to eq(200)

        json = ::JSON.parse(response.body)

        expect(json).to be_present
        expect(json['directory_items'].length).to eq(0)
        expect(json['total_rows_directory_items']).to eq(0)
      end

      it "filters users by group for the user's project groups (different project group)" do
        sign_in(walter_white)

        get '/directory_items.json', params: { period: 'all', group: another_group.name }
        expect(response.status).to eq(200)

        json = ::JSON.parse(response.body)

        expect(json).to be_present
        expect(json['directory_items'].length).to eq(2)
        expect(json['total_rows_directory_items']).to eq(2)
        expect(json['directory_items'][0]['user']['username']).to eq(walter_white.username)
        expect(json['directory_items'][1]['user']['username']).to eq(stage_user.username)
      end
    end
  end
end
