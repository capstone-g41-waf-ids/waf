//initialising the db - creating collections etc.

/*dbAdmin = db.getSiblingDB("admin");

dbAdmin.createUser({
  user: 'root',
  pwd: 'group41',
  roles: [
    {
      role: 'userAdminAnyDatabase',
      db: 'database'
    }
  ]
});

dbAdmin.auth({
  user: "root",
  pwd: "group41",
  mechanisms: ["SCRAM-SHA-1"],
  digestPassword: true,
});

*/
db = new Mongo().getDB("database");

//db.createCollection('TestCollection', { capped: false }); //just for testing, delete later
db.createCollection('WAFLogs', { capped: false });
db.createCollection('UserAccounts', { capped: false });
db.createCollection('WAFFilters', { capped: false });
db.createCollection('IPBlacklist', { capped: false });
db.createCollection('CountryBlacklist', { capped: false });
db.createCollection('HTTPTypes', { capped: false });

exportFile();

function exportFile() {
  mongoClient=new MongoClient(new Server("localhost", 27017, {native_parse:true}));
  mongoClient.open(function(err,mongoClient) {
    db.collection(options.collection),find().toArray(function(err,results) {
      if (err) {
          console.log(err);
          return;
      }
      fs.writeFile("blacklist.txt", JSON.stringify(results),function(err) {
        if (err) {
          console.log(err);
          return;
        }
        console.log(["Connected to: localhost, exported " + results.length + " records"].join("\n"));
        mongoClient.close();
      });
    });
  });
}
//db.TestCollection.insert([{ "TestItem": 1 },]); //just for testing, delete later