//initialising the db - creating collections etc.

db = new Mongo().getDB("database");

//db.createCollection('TestCollection', { capped: false }); //just for testing, delete later
db.createCollection('WAFLogs', { capped: false });
db.createCollection('UserAccounts', { capped: false });
db.createCollection('WAFFilters', { capped: false });
db.createCollection('IPBlacklist', { capped: false });
db.createCollection('CountryBlacklist', { capped: false });
db.createCollection('HTTPTypes', { capped: false });

//db.TestCollection.insert([{ "TestItem": 1 },]); //just for testing, delete later