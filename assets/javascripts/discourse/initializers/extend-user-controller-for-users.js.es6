import { default as computed } from "ember-addons/ember-computed-decorators";
import UserController from 'discourse/controllers/user';
import CanCheckEmails from "discourse/mixins/can-check-emails";
import User from "discourse/models/user";
import optionalService from "discourse/lib/optional-service";

export default {
  name: 'extend-user-controller-for-users',
  initialize() {
    UserController.reopen({
      @computed("model")
      canViewFullProfile(model) {
        let currentUser = this.currentUser;
        let result = (currentUser.admin) || (currentUser.name === model.name);
        return result;
      }
    })
  }
}
