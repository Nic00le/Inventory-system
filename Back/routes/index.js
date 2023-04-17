var express = require('express');
var router = express.Router();

var MongoClient = require('mongodb').MongoClient;
var ObjectId = require('mongodb').ObjectId;
var url = 'mongodb://groupa:PbVj4RTeoidjiiRc@ac-ff0viyj-shard-00-00.vskelan.mongodb.net:27017,ac-ff0viyj-shard-00-01.vskelan.mongodb.net:27017,ac-ff0viyj-shard-00-02.vskelan.mongodb.net:27017/?ssl=true&replicaSet=atlas-r4464l-shard-0&authSource=admin&retryWrites=true&w=majority';

const { v4: uuidv4 } = require('uuid');
var jwt = require('jsonwebtoken');
const auth = require("../middlewares/auth");
const { token } = require('morgan');

const bcrypt = require('bcrypt');
const saltRounds = 10;

var db;

MongoClient.connect(url, function (err, client) {
  db = client.db('bookingsDB');
  console.log("DB connected");
});

//hash login
router.post('/createUser', async function(req, res, next) {
  let user = req.body;
  const salt = bcrypt.genSaltSync(saltRounds);
  const hash = bcrypt.hashSync(user.password, salt);

  try {
    const result = await db.collection('users').insertOne({
      username: user.username,
      password: hash,
      role: user.role
    });
    return res.status(201).json(result);
  } catch(e) {
    return res.status(500).json(e);
  }
});

//HASH LOGIN
router.post('/api/hashlogin', async function(req, res, next) {
  let user = req.body;
  try {
    const result = await db.collection('users').findOne({
      username: user.username,
    });
    
    if (result) {
      const match = bcrypt.compareSync(user.password, result.password);
      if (match) {
        delete result.password;
        // you will need to combie JWT token with user information here.

        const user = {};

    const token = jwt.sign(
      {
        user_id: result._id
      }, "process.env.TOKEN_KEY", {
      expiresIn: "2h",
    }
    );

    user.token = token;
    user.role = result.type;
    user.userId = result._id;
        return res.status(200).json(user);
        
      } else {
        return res.status(401).json({message: 'Incorrect password'});
      }
    } else {
      return res.status(401).json({message: 'User not found'});
    }
  } catch(e) {
    return res.status(500).json(e);
  }
});

/* GET home page. */
router.get('/', function (req, res, next) {
  res.render('index', { title: 'Express' });
});

router.get('/api/users/display', async function (req, res) {
  var whereClause = {};
  var perPage = Math.max(req.query.perPage, 8) || 8;

  var results = await db.collection("users").find(whereClause, {
    limit: perPage,
    skip: perPage * (Math.max(req.query.page - 1, 0) || 0)
  }).toArray();
  console.log(results)

  var pages = Math.ceil(await db.collection("users").count() / perPage);

  return res.json({ records: results, pages: pages })

});

router.post("/api/user/login", async function (req, res) {

  var result = await db.collection("users").findOne({ email: req.body.email });
  console.log(result)

  if (req.body.password == result.password) {
    console.log(result._id)

    const user = {};

    const token = jwt.sign(
      {
        user_id: result._id
      }, "process.env.TOKEN_KEY", {
      expiresIn: "2h",
    }
    );

    user.token = token;
    user.type = result.type;
    user.userId = result._id;


    return res.json(user);

  } else {
    res.status(401).send("Invalid Credentials");

  }

});

/* Handle the form */
router.post('/api/user/create', async function (req, res) {

  let result = await db.collection("users").insertOne(req.body);
  res.status(201).json({ id: result.insertedId });

});

// Form for updating a single Booking 
router.get('/api/user/detail/:id', async function (req, res) {

  if (!ObjectId.isValid(req.params.id))
    return res.status(404).send('Unable to find the requested resource!');

  let result = await db.collection("users").findOne({ _id: ObjectId(req.params.id) });

  if (!result) return res.status(404).send('Unable to find the requested resource!');

  res.json(result);

});

router.put('/api/user/update/:id', async function (req, res) {

  if (!ObjectId.isValid(req.params.id))
    return res.status(404).send('Unable to find the requested resource!');

  var result = await db.collection("users").findOneAndReplace(
    { _id: ObjectId(req.params.id) }, req.body
  );

  if (!result.value)
    return res.status(404).send('Unable to find the requested resource!');

  res.send("User updated.");

});

router.delete('/api/user/delete/:id', async function (req, res) {

  if (!ObjectId.isValid(req.params.id))
    return res.status(404).send('Unable to find the requested resource!');

  let result = await db.collection("users").findOneAndDelete({ _id: ObjectId(req.params.id) })

  if (!result.value) return res.status(404).send('Unable to find the requested resource!');

  return res.status(204).send();

});

/* Handle the form */
router.post('/api/:type/detail', async function (req, res) {

  let result = await db.collection("records").insertOne(req.body);
  res.status(201).json({ id: result.insertedId });

});


router.get('/api/search/:input', async function (req, res) {

  var whereClause = {};
  var page;

  var whereClause = { $or: [{ "title": { $regex: req.params.input } }, { "descriptions": { $regex: req.params.input } }] };
  console.log(whereClause)

  var perPage = Math.max(req.query.perPage, 6) || 6;

  var results = await db.collection("records").find(whereClause, {
    limit: perPage,
    skip: perPage * (Math.max(req.query.page - 1, 0) || 0)
  }).toArray();

  var pages = Math.ceil(await db.collection("records").count(whereClause) / perPage);
  console.log(pages)

  return res.json({ records: results, pages: pages, page: page, perPage: perPage });
});


router.get('/api/:type', async function (req, res) {
  var whereClause = {};
  whereClause.type = req.params.type;
  var perPage = Math.max(req.query.perPage, 6) || 6;

  var pipelines = [
    { $match: { type: req.params.type } },
    {
      $lookup:
      {
        from: "join",
        localField: "_id",
        foreignField: "itemId",
        as: "comsume"
      }
    },
    { $skip: perPage * (Math.max(req.query.page - 1, 0) || 0)},
    { $limit: perPage }
  ]

  let results = await db.collection("records").aggregate(pipelines).toArray();

  console.log(results[0].comsume.length)
  
  var pages = Math.ceil(await db.collection("records").count(whereClause) / perPage);

  return res.json({ records: results, pages: pages })

});

// Form for updating a single Booking 
router.get('/api/records/:id', async function (req, res) {

  if (!ObjectId.isValid(req.params.id))
    return res.status(404).send('Unable to find the requested resource!');

  let result = await db.collection("records").findOne({ _id: ObjectId(req.params.id) });

  if (!result) return res.status(404).send('Unable to find the requested resource!');

  res.json(result);

});

router.put('/api/record/update/:id', async function (req, res) {

  if (!ObjectId.isValid(req.params.id))
    return res.status(404).send('Unable to find the requested resource!');

  var result = await db.collection("records").findOneAndReplace(
    { _id: ObjectId(req.params.id) }, req.body
  );

  if (!result.value)
    return res.status(404).send('Unable to find the requested resource!');

  res.send("Record updated.");

});

router.delete('/api/record/delete/:id', async function (req, res) {

  if (!ObjectId.isValid(req.params.id))
    return res.status(404).send('Unable to find the requested resource!');

  let result = await db.collection("records").findOneAndDelete({ _id: ObjectId(req.params.id) })

  if (!result.value) return res.status(404).send('Unable to find the requested resource!');

  return res.status(204).send();

});

router.post('/api/user/borrow/:id', async function (req, res) {
  const token = req.body.token || req.query.token || req.headers["x-access-token"];

  const decoded = jwt.verify(token, "process.env.TOKEN_KEY");

  let record = await db.collection("users").findOne({_id: ObjectId(decoded.user_id)})

  let result = await db.collection("records").updateOne({ _id: ObjectId(req.params.id) }, { $set: { borrow: {borrowerId: ObjectId(decoded.user_id), borrowerName: record.name}} })


  res.status(201).json({ id: result.insertedId });

});

router.post('/api/user/return/:id', async function (req, res) {
  const token = req.body.token || req.query.token || req.headers["x-access-token"];

  const decoded = jwt.verify(token, "process.env.TOKEN_KEY");

  let record = await db.collection("users").findOne({_id: ObjectId(decoded.user_id)})

  let result = await db.collection("records").updateOne({ _id: ObjectId(req.params.id) },{ $unset: { borrow: {borrowerId: ObjectId(decoded.user_id), borrowerName: record.name}} });

  res.status(201).json({ id: result.insertedId });

});

router.post("/api/user/comsume/:id", async function (req, res) {
  const token = req.body.token || req.query.token || req.headers["x-access-token"];

  const decoded = jwt.verify(token, "process.env.TOKEN_KEY");

  let result = await db.collection("join").insertOne({
    userId: ObjectId(decoded.user_id),
    itemId: ObjectId(req.params.id)
  });

  res.status(201).json({ id: result.insertedId });

});


// GroupBy
router.get('/api/records/aggregate/groupby', auth, async function (req, res) {

  const pipeline = [
    { $match: { type: { $ne: null } } },
    { $group: { _id: "$type", count: { $sum: 1 } } }
  ];

  const results = await db.collection("records").aggregate(pipeline).toArray();

  return res.json(results);

});

module.exports = router;