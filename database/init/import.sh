mongoimport --db database --collection WAFLogs --file "../seed/WAFLogs.json" --jsonArray
mongoimport --db database --collection CountryBlacklist --file "../seed/CountryBlacklist.json" --jsonArray
mongoimport --db database --collection HTTPTypes --file "../seed/HTTPTypes.json" --jsonArray
mongoimport --db database --collection IPBlacklist --file "../seed/IPBlacklist.json" --jsonArray 
mongoimport --db database --collection UserAccounts --file "../seed/UserAccounts.json" --jsonArray
mongoimport --db database --collection WAFFilters --file "../seed/WAFFilters.json" --jsonArray 