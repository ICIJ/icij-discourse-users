import { popupAjaxError } from 'discourse/lib/ajax-error';
import Group from 'discourse/models/group';
import User from 'discourse/models/user';
import { default as computed, observes } from 'ember-addons/ember-computed-decorators';
import debounce from 'discourse/lib/debounce';
import { ajax } from 'discourse/lib/ajax';

export default Ember.Controller.extend({
  queryParams: ['order', 'desc', 'filter'],
  order: '',
  desc: null,
  loading: false,
  filter: null,
  filterInput: null,
  application: Ember.inject.controller(),

  @observes("filterInput")
  _setFilter: debounce(function() {
    this.set("filter", this.get("filterInput"));
  }, 500),

  @observes('order', 'desc', 'filter')
  refreshMembers() {
    return ajax('all-users-in-groups.json', {
      data: _.extend(
        (this.get('memberParams')) || {}
      )}).then(result => {
        this.setProperties({
          members: result.members.map(member => {
            return User.create(member);
          })
        })
      });
    },


  @computed('order', 'desc', 'filter')
  memberParams(order, desc, filter) {
    return { order, desc, filter };
  },

  @computed('model.members')
  hasMembers(members) {
    return members && members.length > 0;
  },

  @computed
  filterPlaceholder() {
    if (this.currentUser && this.currentUser.admin) {
      return "groups.members.filter_placeholder_admin";
    } else {
      return "groups.members.filter_placeholder";
    }
  },

  actions: {
    toggleActions() {
      this.toggleProperty("showActions");
    }
  }
  });
