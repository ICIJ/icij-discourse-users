import debounce from "discourse/lib/debounce";
import { i18n } from "discourse/lib/computed";
import User from "discourse/models/user";
import { observes } from "ember-addons/ember-computed-decorators";

export default Ember.Controller.extend({
  query: null,
  queryParams: ["order", "ascending"],
  order: null,
  ascending: null,
  showEmails: false,
  refreshing: false,
  listFilter: null,
  selectAll: false,

  queryNew: Em.computed.equal("query", "new"),
  queryPending: Em.computed.equal("query", "pending"),
  queryHasApproval: Em.computed.or("queryNew", "queryPending"),
  searchHint: i18n("search_hint"),
  hasSelection: Em.computed.gt("selectedCount", 0),

  _filterUsers: debounce(function() {
    this._refreshUsers();
  }, 250).observes("listFilter"),

  @observes("order", "ascending")
  _refreshUsers: function() {
    this.set("refreshing", true);

    User.findAllIcijUsers(this.get("query"), {
      filter: this.get("listFilter"),
      order: this.get("order"),
      ascending: this.get("ascending")
    })
      .then(result => {
        console.log(this.get("listFilter"));
        this.set("model", result);
      })
      .finally(() => {
        this.set("refreshing", false);
      });
  }
});
