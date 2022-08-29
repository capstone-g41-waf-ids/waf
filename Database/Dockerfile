FROM mongo
EXPOSE 27017

db.createCollection('WAFLogs', { capped: false });
db.createCollection('UserAccounts', { capped: false });
db.createCollection('WAFFilters', { capped: false });
db.createCollection('IPBlacklist', { capped: false });
db.createCollection('CountryBlacklist', { capped: false });
db.createCollection('HTTPTypes', { capped: false });


