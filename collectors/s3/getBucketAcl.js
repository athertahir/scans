var index = require(__dirname + '/index.js');

module.exports = function(AWSConfig, collection, callback) {
	console.log('Begin getBucketAcl');
	index('getBucketAcl', false, AWSConfig, collection, callback);
};