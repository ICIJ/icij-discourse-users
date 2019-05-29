import User from "discourse/models/user";

export default Discourse.Route.extend({
  model: function(params) {
    return User.findAllIcijUsers();
  },

  setupController: function(controller, model) {
    controller.setProperties({
      model: model,
      refreshing: false
    });
  }
});
