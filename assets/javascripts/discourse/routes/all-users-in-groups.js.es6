import { ajax } from 'discourse/lib/ajax';
import User from "discourse/models/user";

export default Ember.Route.extend({

  model(params) {
    this._params = params;
    return ajax('all-users-in-groups.json').then(result => {
      return Ember.Object.create({
        members: result["members"].map(m => User.create(m))
      });
    });
  },

  setupController(controller, model) {

    controller.setProperties({
      model,
      filterInput: this._params.filter
    });

    controller.refreshMembers();
  },

  actions: {
    didTransition() {
      this.controllerFor("all-users-in-groups").set("filterInput", this._params.filter);
      return true;
    }
  }
});
