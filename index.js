const express = require("express");
const cors = require("cors");
const port = process.env.PORT || 5000;
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

require("dotenv").config();

const app = express();

app.use(express.json());
app.use(cors());

app.get("/", (req, res) => {
  res.send(`from port ${port}`);
});

const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const verifyJWT = require("./verifyJWT");
const uri = `mongodb+srv://smdshakibmia2001:${process.env.password}@cluster0.v1wxtqe.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
    useUnifiedTopology: true,
  },
});
const saltRounds = 10;

async function run() {
  try {
    await client.connect();
    const usersCollection = client.db("edupointctg").collection("users");

    app.post("/register", async (req, res) => {
      const { email } = req.body;
      const exist = await usersCollection.findOne({ email });

      if (!exist) {
        const { body } = req;
        bcrypt.hash(body.password, saltRounds, async (err, hash) => {
          body.password = hash;

          const cursor = await usersCollection.insertOne(body);

          if (cursor.insertedId) {
            const token = jwt.sign(
              { _id: cursor.insertedId },
              process.env.access_token_secret,
              {
                expiresIn: "1h",
              }
            );

            res.send({ token });
          }
        });
      } else {
        res.status(409).json({ error: "User already exists with this email." });
      }
    });

    app.post("/login", async (req, res) => {
      const { email, password } = req.body;
      const user = await usersCollection.findOne({ email });

      if (user) {
        bcrypt.compare(password, user.password, (err, result) => {
          if (result) {
            const { _id } = user;
            const token = jwt.sign({ _id }, process.env.access_token_secret, {
              expiresIn: "1h",
            });

            res.send({ token });
          } else {
            res.status(403).send({ message: "Incorrect Password" });
          }
        });
      } else {
        res.status(404).send({ message: "No user Found" });
      }
    });

    app.get("/user-with-firebase-auth/:email", async (req, res) => {
      const { email } = req.params;

      const user = await usersCollection.findOne({ email });

      if (user) {
        const { _id } = user;
        const token = jwt.sign({ _id }, process.env.access_token_secret, {
          expiresIn: "1h",
        });

        res.send({ token });
      } else {
        res.status(404).send("User not found");
      }
    });

    app.get("/profile", async (req, res) => {
      const { _id } = jwt.decode(
        req.headers.token,
        process.env.access_token_secret
      );

      const profileData = await usersCollection.findOne({
        _id: new ObjectId(_id),
      });
      res.send(profileData);
    });
  } finally {
  }
}
run().catch(console.dir);

app.listen(port, () => console.log(`listening on port`, port));
