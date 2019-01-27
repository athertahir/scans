var async = require('async');

var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Custom Roles',
    category: 'Custom Roles',
    description: 'Ensure that no custom subscription owner roles are created',
    more_info: 'Ensure that no custom subscription owner roles are created',
    recommended_action: 'Delete Custom Subscription Owner Roles',
    link: 'https://docs.microsoft.com/en-us/azure/role-based-access-control/custom-roles',
    apis: ['customRoles:list'],

    run: function(cache, settings, callback) {
		var results = [];
		var source = {};
		var locations = helpers.locations(settings.govcloud);

		async.each(locations.customRoles, function(location, rcb){
			var customRoles = helpers.addSource(cache, source,
				['customroles', 'list', location]);

			if (!customRoles) return rcb();

			if (customRoles.err || !customRoles.data) {
				helpers.addResult(results, 3,
					'Unable to query custom Roles: ' + helpers.addError(customRoles), location);
				return rcb();
			}

			if (!customRoles.data.length) {
				helpers.addResult(results, 2, 'No existing Custom Roles', location);
			} else {
				for (res in customRoles.data) {
					var customRole = customRoles.data[res];

					if (customRole.properties.isCustom !="true") {
						helpers.addResult(results, 0, 'This is not a Custom Role', location, customRole.id);
					} else {
						helpers.addResult(results, 2, 'This is a Custom Role', location, customRole.id);
					}
				}
			}
			rcb();
		}, function(){
			// Global checking goes here
			callback(null, results, source);
		});
    }
};