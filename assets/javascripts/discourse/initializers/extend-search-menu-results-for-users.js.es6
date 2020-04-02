import { withPluginApi } from "discourse/lib/plugin-api";
import { avatarImg } from "discourse/widgets/post";
import { dateNode } from "discourse/helpers/node";
import RawHtml from "discourse/widgets/raw-html";
import { createWidget } from "discourse/widgets/widget";
import { h } from "virtual-dom";
import highlightText from "discourse/lib/highlight-text";
import { escapeExpression, formatUsername } from "discourse/lib/utilities";
import { iconNode } from "discourse-common/lib/icon-library";
import renderTag from "discourse/lib/render-tag";
import Site from "discourse/models/site";
import User from "discourse/models/user";

function reconstructAttrs(attrs, grouped) {
  let fellowProjectMembers = User.currentProp("fellow_icij_project_members");

  let users = attrs.results.users.filter(u => {
    return fellowProjectMembers.includes(u.id)
  });

  users = users.map(u => u.id)

  let newGrouped = {
    can_create_topic: grouped.can_create_topic,
    category_ids: grouped.category_ids,
    error: grouped.error,
    group_ids: grouped.group_ids,
    more_categories: grouped.more_categories,
    more_full_page_results: grouped.more_full_page_results,
    more_posts: grouped.more_posts,
    more_users: grouped.more_users,
    post_ids: grouped.post_ids,
    search_log_id: grouped.search_log_id,
    term: grouped.term,
    user_ids: users
  }

  let newAttrs = {
    invalidTerm: attrs.invalidTerm,
    noResults: attrs.noResults,
    results: {
      categories: attrs.results.categories,
      grouped_search_result: newGrouped,
      groups: attrs.results.groups,
      posts: attrs.results.posts,
      resultTypes: attrs.results.resultTypes,
      tags: attrs.results.tags,
      topics: attrs.results.topics,
      users: users
    },
    searchContextEnabled: attrs.searchContextEnabled,
    term: attrs.term
  }

  return newAttrs
}

function initializePlugin(api) {

  api.reopenWidget("search-menu-results", {

    html(attrs) {
      if (attrs.invalidTerm) {
        return h("div.no-results", I18n.t("search.too_short"));
      }

      if (attrs.noResults) {
        return h("div.no-results", I18n.t("search.no_results"));
      }

      let grouped = attrs.results.grouped_search_result
      let newAttrs = reconstructAttrs(attrs, grouped)

      const resultTypes = newAttrs.results.resultTypes || [];

      const mainResultsContent = [];
      const usersAndGroups = [];
      const categoriesAndTags = [];
      const usersAndGroupsMore = [];
      const categoriesAndTagsMore = [];

      const buildMoreNode = result => {
        const more = [];

        const moreArgs = {
          className: "filter",
          contents: () => [I18n.t("more"), "..."]
        };

        if (result.moreUrl) {
          more.push(
            this.attach("link", $.extend(moreArgs, { href: result.moreUrl }))
          );
        } else if (result.more) {
          more.push(
            this.attach(
              "link",
              $.extend(moreArgs, {
                action: "moreOfType",
                actionParam: result.type,
                className: "filter filter-type"
              })
            )
          );
        }

        if (more.length) {
          return more;
        }
      };

      const assignContainer = (result, node) => {
        if (["topic"].includes(result.type)) {
          mainResultsContent.push(node);
        }

        if (["user", "group"].includes(result.type)) {
          usersAndGroups.push(node);
          usersAndGroupsMore.push(buildMoreNode(result));
        }

        if (["category", "tag"].includes(result.type)) {
          categoriesAndTags.push(node);
          categoriesAndTagsMore.push(buildMoreNode(result));
        }
      };

      resultTypes.forEach(rt => {

        let resultNodeContents;
        if (rt.type === "user") {
          let fellowProjectMembers = User.currentProp("fellow_icij_project_members");
          resultNodeContents = [
            this.attach(rt.componentName, {
              searchContextEnabled: newAttrs.searchContextEnabled,
              searchLogId: newAttrs.results.grouped_search_result.search_log_id,
              results: rt.results.filter(u => {
                return fellowProjectMembers.includes(u.id)
              }),
              term: newAttrs.term
            })
          ]
        } else {
          resultNodeContents = [
            this.attach(rt.componentName, {
              searchContextEnabled: newAttrs.searchContextEnabled,
              searchLogId: newAttrs.results.grouped_search_result.search_log_id,
              results: rt.results,
              term: newAttrs.term
            })
          ]
        }

        if (["topic"].includes(rt.type)) {
          const more = buildMoreNode(rt);
          if (more) {
            resultNodeContents.push(h("div.show-more", more));
          }
        }

        assignContainer(rt, h(`div.${rt.componentName}`, resultNodeContents));
      });

      const content = [];

      if (mainResultsContent.length) {
        content.push(h("div.main-results", mainResultsContent));
      }

      if (usersAndGroups.length || categoriesAndTags.length) {
        const secondaryResultsContents = [];

        secondaryResultsContents.push(usersAndGroups);
        secondaryResultsContents.push(usersAndGroupsMore);

        if (usersAndGroups.length && categoriesAndTags.length) {
          secondaryResultsContents.push(h("div.separator"));
        }

        secondaryResultsContents.push(categoriesAndTags);
        secondaryResultsContents.push(categoriesAndTagsMore);

        const secondaryResults = h(
          "div.secondary-results",
          secondaryResultsContents
        );

        content.push(secondaryResults);
      }

      return content;
    }
  });
};

export default {
  name: "extend-search-menu-results-for-users",
  initialize() {
    withPluginApi("0.8.37", api => initializePlugin(api));
  }
}
